package org.jruby.pg.messages;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Base64;
import java.util.Properties;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

//
// AuthenticationSCRAM - PARTIAL IMPLEMENTATION
//
// https://www.rfc-editor.org/rfc/rfc5802
//
public class AuthenticationSCRAM extends BackendMessage {

  // CONST DATA
  public static final int    AUTH_REQ_SASL          = 10;
  public static final int    AUTH_REQ_SASL_CONTINUE = 11;
  public static final int    AUTH_REQ_SASL_FINAL    = 12;
  public static final int    SCRAM_RAW_NONCE_LEN    = 18;
  public static final int    SCRAM_KEY_LEN          = 32;
  public static final String SCRAM_MECHANISM        = "SCRAM-SHA-256";

  public static final String SCRAM_HMAC_SHA_256     = "HmacSHA256";

  // TYPES

  public enum Step {
    Invalid,
    Start,
    Continue
  }

  //
  // ...
  //
  // nonce		            = "r=" c-nonce [s-nonce] ;; Second part provided by server.
  // c-nonce		          = printable
  // s-nonce		          = printable
  // salt			            = "s=" base64
  // iteration-count      = "i=" posit-number ;; A positive number.
  // 
  // server-first-message = [reserved-mext ","] nonce "," salt "," iteration-count ["," extensions]
  //
  private static class ServerFirstMessage 
  {

    private String  mRaw;
    private String  mNonce;
    private String  mSalt;
    private Integer mIterationCount;

    public ServerFirstMessage (final String message) {
      mRaw = message;
      final String [] elements = mRaw.split(",");
      for ( String element : elements ) {
        if ( element.startsWith("r=") ) {
          mNonce = element.substring(2);
        } else if ( element.startsWith("s=") ) {
          mSalt = element.substring(2);
        } else if ( element.startsWith("i=") ) {
          mIterationCount = Integer.parseInt(element.substring(2));
        }
      }
    }

    public final String raw ()  {
      return mRaw;
    }

    public final String nonce ()  {
      return mNonce;
    }

    public final String salt ()  {
      return mSalt;
    }

    public final Integer iterationCount ()  {
      return mIterationCount;
    }

  }

  //
  // ClientMessagesBuilder
  //
  private static final class ClientMesssagesBuilder 
  {

    private final SecureRandom mSecureRandom;
    private       String       mClientFirstMessageBare;
  

    // Default constructor.
    public ClientMesssagesBuilder ()
    {
      mSecureRandom = new SecureRandom();
    }

    //
    // Returns a random generated string, composed of ASCII printable characters except comma.
    //
    private final String nonce () {
      int r;
      byte [] bytes = new byte[SCRAM_RAW_NONCE_LEN];
      for ( int i = 0; i < SCRAM_RAW_NONCE_LEN; ) {
          // ... ASCII printable characters ...
          r = mSecureRandom.nextInt(/* max */ 0x7e - /* min */ 0x21 + 1) + /* min */ 0x21;
          // ... except ',' ...
          if( 0x2c != r ) {
              bytes[i++] = (byte) r;
          }
      }
      return Base64.getEncoder().encodeToString(bytes);
    }

    //
    // ...
    //
    // gs2-cbind-flag  = ("p=" cb-name) / "n" / "y"
    //                      ;; "n" -> client doesn't support channel binding.
    //                      ;; "y" -> client does support channel binding
    //                      ;;        but thinks the server does not.
    //                      ;; "p" -> client requires channel binding.
    //                      ;; The selected channel binding follows "p=".
    //
    // gs2-header      = gs2-cbind-flag "," [ authzid ] ","
    //                   ;; GS2 header for SCRAM
    //                   ;; (the actual GS2 header includes an optional
    //                   ;; flag to indicate that the GSS mechanism is not
    //                   ;; "standard", but since SCRAM is "standard", we
    //                   ;; don't include that flag).
    //
    // username                  = "n=" saslname ;; Usernames are prepared using SASLprep.
    //
    // nonce                     = "r=" c-nonce [s-nonce] ;; Second part provided by server.
    //
    // client-first-message-bare = [reserved-mext ","] username "," nonce ["," extensions]
    // client-first-message      = gs2-header client-first-message-bare
    //
    // @ based on PostgreSQL - based on PostgreSQL - src/interfaces/libpq/fe-auth-scram.c - build_client_first_message
    //
    private byte [] buildFirstMessage (final String a_username) {

        // "n"  -> client doesn't support channel binding.
        // ","  -> [reserved-mext ","]
        // "n=" -> username
        // "r=" -> nonce, second part provided by server.

        mClientFirstMessageBare  = "n=" + a_username + ",r=" + nonce();

        final String message = "n,," + mClientFirstMessageBare;

        final byte[] mechanismNameBytes = SCRAM_MECHANISM.getBytes(StandardCharsets.UTF_8);
        final byte[] messageBytes       = message.getBytes(StandardCharsets.UTF_8);

        final int     len = (mechanismNameBytes.length + 1) + 4 + messageBytes.length;
        byte []       bytes = new byte[len];
        int           idx = 0;
        // ... scram mechanism name ...
        for ( int i = 0 ; i < mechanismNameBytes.length; i++) {
          bytes[idx++] = mechanismNameBytes[i];
        }
        bytes[idx++] = '\0';
        // ... first message size  ...
        bytes[idx++] = (byte) (messageBytes.length >>> 24);
        bytes[idx++] = (byte) (messageBytes.length >>> 16);
        bytes[idx++] = (byte) (messageBytes.length >>> 8);
        bytes[idx++] = (byte) (messageBytes.length);
        // ... first message payload ...
        for ( int i = 0 ; i < messageBytes.length; i++) {
          bytes[idx++] = messageBytes[i];
        }
        // ... done ...
        return bytes;
    }

    //
    // ...
    //
    // channel-binding = "c=" base64            ;; base64 encoding of cbind-input.
    // nonce           = "r=" c-nonce [s-nonce] ;; Second part provided by server.
    // proof           = "p=" base64      
    //
    // client-final-message-without-proof = channel-binding "," nonce ["," extensions]
    // client-final-message = client-final-message-without-proof "," proof
    //
    // @ based on PostgreSQL - src/interfaces/libpq/fe-auth-scram.c - build_client_final_message
    //
    public byte[] buildFinalMessage (final String password, final String client_first_message_bare, final ServerFirstMessage server_first_message ) throws IOException {
      final String c = /* channel-binding */ "c=biws";                            // we are not using channel binding, the binding data is expected to always be "biws", which is "n,,"
      final String r = /* nonce           */ "r=" + server_first_message.nonce(); // the same sent on the first message
      final String m = /*                 */ c + "," + r;                         // client_final_message_without_proof
      final String p = /* proof           */ "p=" + Base64.getEncoder().encodeToString(
          ClientMesssagesBuilder.calculateProof(server_first_message.salt(), password, server_first_message.iterationCount(), client_first_message_bare, server_first_message.raw(), m)
      );
      // ... done ...
      return (m + "," + p).getBytes(); // client-final-message
    }

    //
    // @ based on PostgreSQL - src/interfaces/libpq/fe-auth-scram.c - calculate_client_proof
    //
    public static byte[] calculateProof (final String salt, final String password, final int iteration_count, final String client_first_message_bare, final String server_first_message, final String client_final_message_without_proof) {

      // ... calculate salted password ...
      final byte [] calculated_salted_password_bytes = calculateSaltedPassword(Base64.getDecoder().decode(salt), password, iteration_count);
      // ... calculate client key ...
      final byte[] calculated_client_key = calculateKey(calculated_salted_password_bytes);
      // ... calculate stored key ...
      final byte[] calculated_stored_key = SHA256(calculated_client_key);
      // ... calculate proof ...
      byte[] calculated_proof;

      try {

        javax.crypto.Mac mac = javax.crypto.Mac.getInstance(SCRAM_HMAC_SHA_256);

        mac.init(new SecretKeySpec(calculated_stored_key, SCRAM_HMAC_SHA_256));

        mac.update(client_first_message_bare.getBytes(StandardCharsets.UTF_8));
        mac.update(",".getBytes(StandardCharsets.UTF_8));

        mac.update(server_first_message.getBytes(StandardCharsets.UTF_8));
        mac.update(",".getBytes(StandardCharsets.UTF_8));

        mac.update(client_final_message_without_proof.getBytes(StandardCharsets.UTF_8));

        final byte[] calculated_client_signature = mac.doFinal();

        // ... xor ...
        calculated_proof = new byte[SCRAM_KEY_LEN];
        for(int i = 0; i < SCRAM_KEY_LEN; i++) {
            calculated_proof[i] = (byte) (calculated_client_key[i] ^ calculated_client_signature[i]);
        }

      } catch (java.security.InvalidKeyException k) {
        throw new IllegalArgumentException(k);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalArgumentException(e);
      }
      // ... done ...
      return calculated_proof;
    }

    //
    // @ based on PostgreSQL - src/backend/libpq/auth-scram.c - verify_client_proof
    //
    public static boolean verifyProof (final byte[] stored_key, final String client_first_message_bare, final String server_first_message, final String client_final_message_without_proof, final byte[] proof) {

      try {

        javax.crypto.Mac mac = javax.crypto.Mac.getInstance(SCRAM_HMAC_SHA_256);

        mac.init(new SecretKeySpec(stored_key, SCRAM_HMAC_SHA_256));
        mac.update(client_first_message_bare.getBytes(StandardCharsets.UTF_8));
        mac.update(",".getBytes(StandardCharsets.UTF_8));
        mac.update(server_first_message.getBytes(StandardCharsets.UTF_8));
        mac.update(",".getBytes(StandardCharsets.UTF_8));
        mac.update(client_final_message_without_proof.getBytes(StandardCharsets.UTF_8));

        final byte[] client_signature = mac.doFinal();

        final byte[] client_key = new byte[SCRAM_KEY_LEN];
        // ... xor ...
        for ( int i = 0; i < SCRAM_KEY_LEN; i++ ) {
            client_key[i] = (byte) (proof[i] ^ client_signature[i]);
        }

        final byte[] client_stored_key = SHA256(client_key);
        for ( int i = 0; i < SCRAM_KEY_LEN; i++ ) {
            if ( client_stored_key[i] != stored_key[i] ) {
              // ... failed ...
              return false;
            }
        }

      } catch (java.security.InvalidKeyException k) {
        throw new IllegalArgumentException(k);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalArgumentException(e);
      }
      // ... succeded ...
      return true;
    }

    //
    // Calculate SHA-256 hash for a NULL-terminated string. 
    // (The NULL terminator is not included in the hash).
    //
    private static byte [] SHA256 (final byte[] input)
    {
      byte[] result = null;
      try {
        result = MessageDigest.getInstance("SHA-256").digest(input);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalArgumentException(e);
      }
      // ... done ...
      return result;
    }

    //
    // @ based on PostgreSQL - src/interfaces/libpq/scram-common.c - scram_ClientKey
    //
    private final static byte [] calculateKey (final byte[] salted_password) {
      byte[] result = new byte[SCRAM_KEY_LEN];
      try {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance(SCRAM_HMAC_SHA_256);
        mac.init(new SecretKeySpec(salted_password, SCRAM_HMAC_SHA_256));
        mac.update("Client Key".getBytes(StandardCharsets.UTF_8));
        return mac.doFinal();
      } catch (java.security.InvalidKeyException k) {
        throw new IllegalArgumentException(k);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalArgumentException(e);
      }
    }

    //
    // @ based on PostgreSQL - src/interfaces/libpq/scram-common.c - scram_SaltedPassword
    //
    private static byte[] calculateSaltedPassword (final byte[] salt, final String password, final int iterations) {
      byte[] result = new byte[SCRAM_KEY_LEN];
      try {
        //
        final byte[]           one = java.nio.ByteBuffer.allocate(4).putInt(1).array();
        final javax.crypto.Mac mac = javax.crypto.Mac.getInstance(SCRAM_HMAC_SHA_256);
        // ... first iteration ...
        mac.init(new SecretKeySpec(password.getBytes(StandardCharsets.UTF_8), SCRAM_HMAC_SHA_256));
        mac.update(salt);
        mac.update(one);
        final byte[] previous = mac.doFinal();
        // ... copy ...
        for ( int j = 0; j < SCRAM_KEY_LEN; j++ ) {
          result[j] = previous[j];
        }
        // ... subsequent iterations ...
        for ( int i = 2; i <= iterations; i++ ) {
          // ... init ...
          mac.init(new SecretKeySpec(password.getBytes(StandardCharsets.UTF_8), SCRAM_HMAC_SHA_256));
          // ... update ...
          mac.update(previous);
          // ... calculate current ...
          final byte[] current = mac.doFinal();
          // ... XOR ...
          for ( int j = 0; j < SCRAM_KEY_LEN; j++ ) {
              result[j] = (byte) (result[j] ^ current[j]);
          }
          // ... copy ...
          for ( int j = 0; j < SCRAM_KEY_LEN; j++ ) {
            previous[j] = current[j];
          }
        }

      } catch (java.security.InvalidKeyException k) {
        throw new IllegalArgumentException(k);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalArgumentException(e);
      }
      // ... done ...
      return result;
    }    

  }

  // DATA

  private final Step                   mStep;
  private final ServerFirstMessage     mServerFirstMessage;
  private       ClientMesssagesBuilder mClientMessagesBuilder;

  //
  // Deprecated Constructor - from BackendMessage
  //
  private AuthenticationSCRAM(byte[] data) {
     throw new IllegalArgumentException("Unsupported constructor!");
  }

  @Override
  public MessageType getType() {
    return MessageType.AuthenticationSCRAM;
  }

  public byte[] getSalt() {
      return null;
  }

  //
  // Custom Constructor
  //
  private AuthenticationSCRAM(final Step step, final String message) {
    mStep = step;
    if ( Step.Continue == mStep ) {
      mServerFirstMessage = new ServerFirstMessage(message);
    } else {
      mServerFirstMessage = null;
    }
    mClientMessagesBuilder = new ClientMesssagesBuilder();
  }

  // -- //
  public final Step getStep () {
    return mStep;
  }

  // -- //

  //
  // SCRAMFrontendMessage
  //
  private static class SCRAMFrontendMessage extends FrontendMessage {
    private final byte[] message;

    public SCRAMFrontendMessage(byte[] message) {
      this.message = message;
    }

    @Override
    public void writeInternal(ProtocolWriter writer) {
      writer.writeNChar(message);
    }

    @Override
    public MessageType getType() {
      return MessageType.PasswordMessage;
    }
  }

  //
  // STATIC HELPER(s)
  //

  public static final FrontendMessage SALSClientFirstMessage (final String username, AuthenticationSCRAM auth, Properties props)
  {
      final byte[] firstMessage = auth.mClientMessagesBuilder.buildFirstMessage(username);
      props.setProperty("SCRAMSHA126ClientFirstMessageBare", auth.mClientMessagesBuilder.mClientFirstMessageBare);
      return new AuthenticationSCRAM.SCRAMFrontendMessage(firstMessage);
  }

  public static final FrontendMessage SALSClientFinalMessage(final String password, AuthenticationSCRAM auth, Properties props)
  {
    try {
      return new AuthenticationSCRAM.SCRAMFrontendMessage(
        auth.mClientMessagesBuilder.buildFinalMessage(password, props.getProperty("SCRAMSHA126ClientFirstMessageBare"), auth.mServerFirstMessage)
      );
    } catch (IOException e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static BackendMessage SASLStart (final String mechanism, final String message) 
  {
      if ( false == mechanism.equals(AuthenticationSCRAM.SCRAM_MECHANISM) ) {
          throw new IllegalArgumentException("Unsupported authentication mechanism: " + mechanism + "!");
      }
      return new AuthenticationSCRAM(AuthenticationSCRAM.Step.Start, message);
  }
  public static BackendMessage SASLContinue (final String message)
  {
    return new AuthenticationSCRAM(AuthenticationSCRAM.Step.Continue, message);
  }

  //
  // server-final-message is: (RFC 5802)
  //
  // verifier		         = "v=" base64 ;; base-64 encoded ServerSignature.
  // server-final-message = (server-error / verifier) ["," extensions]
  //
  public static BackendMessage SASLFinal (final String message)
  {
    return new AuthenticationOk();
  }

}
