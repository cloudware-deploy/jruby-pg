#!/usr/bin/env rake
#-*- ruby -*-

require 'rbconfig'
require 'pathname'
require 'tmpdir'

begin
	require 'rake/extensiontask'
rescue LoadError
	abort "This Rakefile requires rake-compiler (gem install rake-compiler)"
end

begin
	require 'hoe'
rescue LoadError
	abort "This Rakefile requires hoe (gem install hoe)"
end

require 'rake/clean'

# Build directory constants
BASEDIR = Pathname( __FILE__ ).dirname
SPECDIR = BASEDIR + 'spec'
LIBDIR  = BASEDIR + 'lib'
EXTDIR  = BASEDIR + 'ext'
PKGDIR  = BASEDIR + 'pkg'
TMPDIR  = BASEDIR + 'tmp'

DLEXT   = RbConfig::CONFIG['DLEXT']
EXT     = LIBDIR + "pg_ext.#{DLEXT}"

TEST_DIRECTORY = BASEDIR + "tmp_test_specs"

CLOBBER.include( TEST_DIRECTORY.to_s )
CLEAN.include( PKGDIR.to_s, TMPDIR.to_s )

# Set up Hoe plugins
#Hoe.plugin :mercurial
#Hoe.plugin :signing
#Hoe.plugin :deveiate
Hoe.plugin :bundler

Hoe.plugins.delete :rubyforge
Hoe.plugins.delete :compiler

def jruby?
  RUBY_PLATFORM =~ /java/
end

# Hoe specification
$hoespec = Hoe.spec jruby? ? 'jruby-pg' : 'pg' do
	#self.readme_file = 'README.rdoc'
	self.history_file = 'History.rdoc'
	self.extra_rdoc_files = Rake::FileList[ '*.rdoc' ]
	self.extra_rdoc_files.include( 'POSTGRES', 'LICENSE' )
	self.extra_rdoc_files.include( 'ext/*.c' )

        self.developer 'Charles Nutter', 'headius@headius.com'
	self.developer 'John Shahid', 'jvshahid@gmail.com'

	self.dependency 'rake-compiler', '~> 0.9', :developer
	self.dependency 'hoe', '~> 3.5.1', :developer
	self.dependency 'hoe-deveiate', '~> 0.2', :developer
	self.dependency 'hoe-bundler', '~> 1.0', :developer

	self.spec_extras[:licenses] = ['BSD-2-Clause', 'Ruby']
	self.spec_extras[:extensions] = [ 'ext/extconf.rb' ] unless jruby?

        self.license 'Ruby'

  self.spec_extras[:files] = Proc.new do |f|
    self.spec_extras[:files] = f << 'lib/pg_ext.jar'
  end if jruby?

	self.require_ruby_version( '>= 1.8.7' )

	self.hg_sign_tags = true if self.respond_to?( :hg_sign_tags= )
	self.check_history_on_release = true if self.respond_to?( :check_history_on_release= )
	self.spec_extras[:rdoc_options] = [
		'-f', 'fivefish',
		'-t', 'pg: The Ruby Interface to PostgreSQL',
		'-m', 'README.rdoc',
	]

	self.rdoc_locations << "deveiate:/usr/local/www/public/code/#{remote_rdoc_dir}"

  self.spec_extras[:platform] = 'java' if jruby?
  self.version = '0.2' if jruby?
end

if jruby?
  require "rake/javaextensiontask"

  Rake::JavaExtensionTask.new("pg_ext", $hoespec.spec) do |ext|
    ext.ext_dir = 'ext/java'
    ext.lib_dir = 'lib'
  end
else
  load 'Rakefile.cross'

  # Rake-compiler task
  Rake::ExtensionTask.new do |ext|
  	ext.name           = 'pg_ext'
  	ext.gem_spec       = $hoespec.spec
  	ext.ext_dir        = 'ext'
  	ext.lib_dir        = 'lib'
  	ext.source_pattern = "*.{c,h}"
  	ext.cross_compile  = true
  	ext.cross_platform = CrossLibraries.map &:for_platform

    ext.cross_config_options += CrossLibraries.map do |lib|
      {
        lib.for_platform => [
          "--with-pg-include=#{lib.static_postgresql_libdir}",
          "--with-opt-include=#{lib.static_postgresql_incdir}",
          "--with-pg-lib=#{lib.static_postgresql_libdir}",
          "--with-opt-lib=#{lib.static_openssl_builddir}",
        ]
      }
    end
  end
end

ENV['VERSION'] ||= $hoespec.spec.version.to_s

# Tests should pass before checking in
task 'hg:precheckin' => [ :check_history, :check_manifest, :spec ]

# Support for 'rvm specs'
task :specs => :spec

# Compile before testing
task :spec => :compile

# gem-testers support
task :test do
	# rake-compiler always wants to copy the compiled extension into lib/, but
	# we don't want testers to have to re-compile, especially since that
	# often fails because they can't (and shouldn't have to) write to tmp/ in
	# the installed gem dir. So we clear the task rake-compiler set up
	# to break the dependency between :spec and :compile when running under
	# rubygems-test, and then run :spec.
	Rake::Task[ EXT.to_s ].clear
	Rake::Task[ :spec ].execute
end

desc "Turn on warnings and debugging in the build."
task :maint do
	ENV['MAINTAINER_MODE'] = 'yes'
end

ENV['RUBY_CC_VERSION'] ||= '1.8.7:1.9.2:2.0.0'

# Make the ChangeLog update if the repo has changed since it was last built
file '.hg/branch' do
	warn "WARNING: You need the Mercurial repo to update the ChangeLog"
end
file 'ChangeLog' do |task|
	if File.exist?('.hg/branch')
		$stderr.puts "Updating the changelog..."
		begin
			content = make_changelog()
		rescue NameError
			abort "Packaging tasks require the hoe-mercurial plugin (gem install hoe-mercurial)"
		end
		File.open( task.name, 'w', 0644 ) do |fh|
			fh.print( content )
		end
	else
		touch 'ChangeLog'
	end
end

# Rebuild the ChangeLog immediately before release
task :prerelease => 'ChangeLog'


desc "Stop any Postmaster instances that remain after testing."
task :cleanup_testing_dbs do
    require 'spec/lib/helpers'
    PgTestingHelpers.stop_existing_postmasters()
    Rake::Task[:clean].invoke
end

desc "Update list of server error codes"
task :update_error_codes do
	URL_ERRORCODES_TXT = "http://git.postgresql.org/gitweb/?p=postgresql.git;a=blob_plain;f=src/backend/utils/errcodes.txt;hb=HEAD"

	ERRORCODES_TXT = "ext/errorcodes.txt"
	sh "wget #{URL_ERRORCODES_TXT.inspect} -O #{ERRORCODES_TXT.inspect} || curl #{URL_ERRORCODES_TXT.inspect} -o #{ERRORCODES_TXT.inspect}"
end

def error_codes_file
  if jruby?
    return 'ext/java/Errors.java'
  else
    'ext/errorcodes.def'
  end
end

file error_codes_file => ['ext/errorcodes.rb', 'ext/errorcodes.txt'] do
	ruby 'ext/errorcodes.rb', 'ext/errorcodes.txt', error_codes_file
end

#file 'ext/pg_errors.c' => ['ext/errorcodes.def'] do
#	# trigger compilation of changed errorcodes.def
#	touch 'ext/pg_errors.c'
#end

file 'ext/java/PgExtService.java' => error_codes_file
