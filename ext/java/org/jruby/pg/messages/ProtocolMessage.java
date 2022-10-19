package org.jruby.pg.messages;


public abstract class ProtocolMessage {
  public static enum MessageType {
    AuthenticationOk('R'),
    AuthenticationKerbosV5('R'),
    AuthenticationCleartextPassword('R'),
    AuthenticationCryptPassword('R'),
    AuthenticationMD5Password('R'),
    AuthenticationSCMCredential('R'),
    AuthenticationSCRAM('R'),
    BackendKeyData('K'),
    Bind('B'),
    BindComplete('2'),
    CancelRequest('\0'),
    Close('C'),
    CloseComplete('3'),
    CommandComplete('C'),
    CopyData('d'),
    CopyDone('c'),
    CopyFail('f'),
    CopyInResponse('G'),
    CopyOutResponse('H'),
    DataRow('D'),
    Describe('D'),
    EmptyQueryResponse('I'),
    ErrorResponse('E'),
    Execute('E'),
    Flush('H'),
    FunctionCall('F'),
    FunctionCallResponse('V'),
    NoData('n'),
    NoticeResponse('N'),
    NotificationResponse('A'),
    ParameterDescription('t'),
    ParameterStatus('S'),
    Parse('P'),
    ParseComplete('1'),
    PasswordMessage('p'),
    PortalSuspended('s'),
    Query('Q'),
    ReadyForQuery('Z'),
    RowDescription('T'),
    SSLRequest('\0'),
    StartupMessage('\0'),
    Sync('S'),
    Terminate('X');

    private MessageType(char firstByte) {
      this.firstByte = (byte) firstByte;
    }

    public final byte firstByte;
  }

  public byte getFirstByte() {
    return getType().firstByte;
  }
  public abstract MessageType getType();
}
