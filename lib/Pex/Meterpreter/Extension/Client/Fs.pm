
###############
##
#
#    Name: Fs.pm
#  Author: skape <mmiller [at] hick.org>
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      This module is a meterpreter extension module that provides
#      the user with the ability to interact with the file system
#      on the remote endpoint.
#
##
###############

use strict;
use Pex::Meterpreter::Channel;
use Pex::Meterpreter::Packet;

package Def;

use constant FILE_TYPE_UNKNOWN           => 0;
use constant FILE_TYPE_REGULAR           => 1;
use constant FILE_TYPE_DIRECTORY         => 2;

use constant FILE_MODE_READ              => (1 << 0);
use constant FILE_MODE_WRITE             => (1 << 1);
use constant FILE_MODE_READWRITE         => (1 << 0) | (1 << 1);

use constant FS_BASE                     => 14100;
use constant TLV_TYPE_FS_PATH            => makeTlv(TLV_META_TYPE_STRING, FS_BASE +  0);
use constant TLV_TYPE_FS_FILE_INFO_GROUP => makeTlv(TLV_META_TYPE_GROUP,  FS_BASE +  1);
use constant TLV_TYPE_FS_FILE_MTIME      => makeTlv(TLV_META_TYPE_UINT,   FS_BASE +  2);
use constant TLV_TYPE_FS_FILE_SIZE       => makeTlv(TLV_META_TYPE_UINT,   FS_BASE +  3);
use constant TLV_TYPE_FS_FILE_TYPE       => makeTlv(TLV_META_TYPE_UINT,   FS_BASE +  4);
use constant TLV_TYPE_FS_TARGET_PATH     => makeTlv(TLV_META_TYPE_STRING, FS_BASE +  0);
use constant TLV_TYPE_FS_SOURCE_PATH     => makeTlv(TLV_META_TYPE_STRING, FS_BASE +  5);
use constant TLV_TYPE_FS_MODE            => makeTlv(TLV_META_TYPE_UINT,   FS_BASE +  6);

package Pex::Meterpreter::Extension::Client::Fs;

my $instance = undef;
my @handlers = 
(
	{
		identifier  => "File System",
		description => "File system interaction and manipulation commands",
		handler     => undef,
	},
	{
		identifier  => "cd",
		description => "Change working directory.",
		handler     => \&Pex::Meterpreter::Extension::Client::Fs::cd,
	},
	{
		identifier  => "getcwd",
		description => "Get the current working directory.",
		handler     => \&Pex::Meterpreter::Extension::Client::Fs::getcwd,
	},
	{
		identifier  => "ls",
		description => "List the contents of a directory.",
		handler     => \&Pex::Meterpreter::Extension::Client::Fs::ls,
	},
	{
		identifier  => "upload",
		description => "Upload one or more files to a remote directory.",
		handler     => \&Pex::Meterpreter::Extension::Client::Fs::upload,
	},
	{
		identifier  => "download",
		description => "Download one or more files from a remote directory.",
		handler     => \&Pex::Meterpreter::Extension::Client::Fs::download,
	},
);

#
# Constructor
#
sub new
{
	my $this  = shift;
	my $class = ref($this) || $this;
	my $self  = {};
	my ($client) = @{{@_}}{qw/client/};

	# If the singleton has yet to be created...
	if (not defined($instance))
	{
		bless($self, $class);

		$self->{'client'} = $client;

		$instance = $self;
	}
	else
	{
		$self = $instance;
	}
		
	$self->registerHandlers(client => $client);

	return $self;
}

sub DESTROY
{
	my $self = shift;

	$self->deregisterHandlers(client => $self->{'client'});
}

##
#
# Dispatch registration 
#
##

sub registerHandlers
{
	my $self = shift;
	my ($client) = @{{@_}}{qw/client/};

	foreach my $handler (@handlers)
	{
		$client->registerLocalInputHandler(
				identifier  => $handler->{'identifier'},
				description => $handler->{'description'},
				handler     => $handler->{'handler'});
	}
}

sub deregisterHandlers
{
	my $self = shift;
	my ($client) = @{{@_}}{qw/client/};

	foreach my $handler (@handlers)
	{
		$client->deregisterLocalInputHandler(
				identifier  => $handler->{'identifier'});
	}
}


##
#
# Local dispatch handlers
#
##

#
# Changes the current working directory of the remote thread
#
sub cdComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};

	return $client->writeConsoleOutputResponse(
			cmd    => 'cd',
			packet => $packet);
}

sub cd
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv   = @{ $argumentsScalar };
	my $argc   = scalar(@argv);
	my $request;

	# Print the banner if no arguments have been supplied
	if ($argc == 1)
	{
		$client->writeConsoleOutput(text => 
				"Usage: cd directory\n");
		goto out;
	}

	# Create the fs_cwd request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "fs_cwd");
	
	# Add the folder to change into
	$request->addTlv(
			type  => Def::TLV_TYPE_FS_PATH,
			value => $argv[1]);
	
	$client->writeConsoleOutput(text =>
			"cd: Changing directory to '" . $argv[1] . "'\n");
	
	# Transmit the request
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&cdComplete);

out:
	return 1;
}

#
# Gets the current working directory of the remote thread
#
sub getcwdComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};
	my $result = $$packet->getResult();

	# If the operation succeeded, print the path
	if ($result == 0)
	{
		my $path = $$packet->getTlv(
				type => Def::TLV_TYPE_FS_PATH);

		$path = "unknown" if (not defined($path));

		$client->writeConsoleOutput(text =>
				"\n" .
				"getcwd: Current directory is '$path'.\n");
		$client->printPrompt();
	}
	else
	{
		$client->writeConsoleOutputResponse(
			cmd    => 'getcwd',
			packet => $packet);
	}

	return 1;
}

sub getcwd
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my $request;

	# Create the request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "fs_getcwd");

	$client->writeConsoleOutput(text =>
			"getcwd: Requesting the cwd\n");

	# Transmit the request
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&getcwdComplete);

	return 1;
}

#
# Lists the contents of the current working directory on the remote endpoint
#
sub lsComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};
	my $result = $$packet->getResult();

	# If the directory listing succeeded...
	if ($result == 0)
	{
		my $fileInfo;
		my $idx = 0;
		my $path;
		
		$path = $$packet->getTlv(
				type => Def::TLV_TYPE_FS_PATH);
	
		# Print the banner
		$client->writeConsoleOutput(text => "\n");

		if (defined($path))
		{
			$client->writeConsoleOutput(text => 
					"Listing: $path\n\n");
		}

		$client->writeConsoleOutput(text =>
				"      Size    Type   Name\n" .
				" ---------   -----   ----------------\n");

		# Enumerate through all the files
		while (defined($fileInfo = $$packet->enumTlv(
				type   => Def::TLV_TYPE_FS_FILE_INFO_GROUP,
				index  => $idx++)))
		{	
			my $realSize;
			my $sizeType;
			my $name;
			my $type;
			my $size;
			my $buf;

			# Extract this file's information
			$name = $$packet->getTlv(
					type   => Def::TLV_TYPE_FS_PATH,
					buffer => $fileInfo);
			$type = $$packet->getTlv(
					type   => Def::TLV_TYPE_FS_FILE_TYPE,
					buffer => $fileInfo);
			$size = $$packet->getTlv(
					type   => Def::TLV_TYPE_FS_FILE_SIZE,
					buffer => $fileInfo);

			# Make a cool size
			if ($size >= (1 << 30))
			{
				$realSize = $size / (1 << 30);
				$sizeType = "GB";
			}
			elsif ($size >= (1 << 20))
			{
				$realSize = $size / (1 << 20);
				$sizeType = "MB";
			}
			elsif ($size >= (1 << 10))
			{
				$realSize = $size / (1 << 10);
				$sizeType = "KB";
			}
			else
			{
				$realSize = $size;
				$sizeType = " B";
			}

			# Determine the file type
			if ($type == Def::FILE_TYPE_REGULAR)
			{
				$type = "REG";
			}
			elsif ($type == Def::FILE_TYPE_DIRECTORY)
			{
				$type = "DIR";
			}
			else
			{
				$type = "UNK";
			}

			$buf = sprintf("%7.2f %s   %5s   %s", 
					$realSize, $sizeType, $type, $name);

			$client->writeConsoleOutput(text =>
					"$buf\n");
		}

		$client->printPrompt();
	}
	else
	{
		$client->writeConsoleOutputResponse(
			cmd    => 'ls',
			packet => $packet);
	}

	return 1;
}

sub ls
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $request;

	# Create the fs_ls request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "fs_ls");

	# If a path was supplied, list it instead of using the current directory
	if ($argc > 1)
	{
		$request->addTlv(
				type  => Def::TLV_TYPE_FS_PATH,
				value => $argv[1]);
	}

	$client->writeConsoleOutput(text =>
			"ls: Requesting a directory listing\n");

	# Transmit the request
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&lsComplete);

	return 1;
}

#
# Uploads one or more files from the local machine to a supplied directory on
# the remote endpoint
#
sub uploadOpenComplete
{
	my ($channel, $result, $client, $ctx) = @{{@_}}{qw/channel result client handlerParameter/};
	my $file = $ctx->{'file'};
	my $printed = 0;
	my $fd;

	# If the channel is invalid or the open failed...
	if ((not defined($channel)) or
	    ($result != 0))
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"Error: The channel could not be opened, $result.\n");
		$result = $printed = 1;
		goto out;
	}

	# Open the local file
	if (not defined(open($fd, "<$file")))
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"Error: Local file '$file' could not be opened for reading.\n");
		$printed = 1;
		$result = 1;
		goto out;
	}

	$ctx->{'fd'} = $fd;

	# Call the write complete handler to kick off the read/upload loop
	uploadWriteComplete(
			client           => $client,
			channel          => $channel,
			result           => $result,
			handlerParameter => $ctx);

out:

	# If the operation failed...
	if ($result != 0)
	{
		# If the channel is valid
		if (defined($channel))
		{
			$$channel->close(
					client => $client);
		}

		# If the fd is valid, close it
		if (defined($fd))
		{
			close $fd;
		}
	}

	$client->printPrompt() if ($printed);

	return 1;
}

sub uploadWriteComplete
{
	my ($channel, $result, $client, $length, $ctx) = @{{@_}}{qw/channel result client length handlerParameter/};
	my $printed = 0;
	my $file = $ctx->{'file'};
	my $done = 0;
	my $fd = $ctx->{'fd'};
	my $buf;

	# Check for success
	if ((not defined($channel)) or
	    ($result != 0))
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"upload: channel_write failed, $result.\n");
		$printed = 1;
		goto out;
	}

	# Read from the file descriptor
	$length = sysread($fd, $buf, 8192);

	if ($length <= 0)
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"upload: Upload from '$file' succeeded.\n");
		$printed = $done = 1;
		goto out;
	}

	# Write the next portion of the buffer
	$$channel->write(
			client                     => $client,
			buffer                     => $buf,
			length                     => $length,
			completionHandler          => \&uploadWriteComplete,
			completionHandlerParameter => $ctx);

out:

	# If the operation failed...
	if (($result != 0) or
	    ($done))
	{
		# If the channel is valid
		if (defined($channel))
		{
			$$channel->close(
					client => $client);
		}

		# If the fd is valid, close it
		if (defined($fd))
		{
			close $fd;
		}
	}

	$client->printPrompt() if ($printed);

	return 1;
}

sub upload
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $remoteFolder;
	my $idx;

	if ($argc < 3)
	{
		$client->writeConsoleOutput(text =>
				"Usage: upload src1 [src2 ...] dst\n");
		goto out;
	}
	
	$remoteFolder = $argv[$argc - 1];

	# Enumerate through all of the upload files
	for ($idx = 1; 
	     $idx < $argc - 1; 
	     $idx++)
	{
		my $handlerParameter = {};
		my $localFileName = $argv[$idx];
		my $rdelimiter = $client->getRemoteFileDelimiter();
		my $remoteFile;

		$localFileName =~ s/.*[\\\/](.*?)$/$1/;
		$remoteFile    = $remoteFolder . $rdelimiter . $localFileName;

		# Initialize the handler parameter hash
		$handlerParameter->{'file'} = $argv[$idx];
		$handlerParameter->{'fd'}   = undef;

		$client->writeConsoleOutput(text =>
				"upload: Starting upload of '" . $argv[$idx] . "' to '" . $remoteFile . "'...\n");

		# Open the file for write
		openFile(
				client                     => $client,
				remoteFile                 => $remoteFile,
				mode                       => Def::FILE_MODE_WRITE,
				completionHandler          => \&uploadOpenComplete,
				completionHandlerParameter => $handlerParameter);
	}

	$client->writeConsoleOutput(text =>
			"upload: " . ($idx - 1) . " uploads started.\n");

out:
	return 1;
}

#
# Downloads one or more files from the remote machine to a supplied directory on
# the local machine
#
sub downloadOpenComplete
{
	my ($channel, $result, $client, $ctx) = @{{@_}}{qw/channel result client handlerParameter/};
	my $file = $ctx->{'file'};
	my $printed = 0;
	my $fd;

	# If the channel is invalid or the open failed...
	if ((not defined($channel)) or
	    ($result != 0))
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"Error: The channel could not be opened, $result.\n");
		$result = $printed = 1;
		goto out;
	}

	# Open the local file for writing
	if (not defined(open($fd, ">$file")))
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"Error: Local file '$file' could not be opened for writing.\n");
		$result = $printed = 1;
		goto out;
	}

	$ctx->{'fd'} = $fd;

	# Kick off the read loop by supplying an invalid buffer to the complete
	# handler
	downloadReadComplete(
			client           => $client,
			channel          => $channel,
			result           => $result,
			buffer           => undef,
			length           => 1,
			handlerParameter => $ctx);

out:

	# If the operation failed...
	if ($result != 0)
	{
		# If the channel is valid
		if (defined($channel))
		{
			$$channel->close(
					client => $client);
		}

		# If the fd is valid, close it
		if (defined($fd))
		{
			close $fd;
		}
	}

	$client->printPrompt() if ($printed);

	return 1;
}

sub downloadReadComplete
{
	my ($channel, $client, $result, $buffer, $length, $ctx) = @{{@_}}{qw/channel client result buffer length handlerParameter/};
	my $file = $ctx->{'file'};
	my $fd = $ctx->{'fd'};
	my $printed = 0;
	my $done = 0;

	# Check for success
	if ((not defined($channel)) or
	    ($result != 0))
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"download: channel_read failed, $result.\n");
		$printed = 1;
		goto out;
	}

	# If the buffer is valid, write it to the file
	if (defined($buffer))
	{
		syswrite($fd, $buffer, $length);
	}

	# Check to see if we've reached the EOF marker
	if ((not defined($length)) or 
	    ($length <= 0))
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"download: Download to '$file' succeeded.\n");
		$printed = $done = 1;
		goto out;
	}

	# Since there is more data to be read, do that now.
	$$channel->read(
			client                     => $client,
			length                     => 8192,
			completionHandler          => \&downloadReadComplete,
			completionHandlerParameter => $ctx);

out:

	# If the operation failed or finished...
	if (($result != 0) or
	    ($done))
	{
		# If the channel is valid
		if (defined($channel))
		{
			$$channel->close(
					client => $client);
		}

		# If the fd is valid, close it
		if (defined($fd))
		{
			close $fd;
		}
	}

	$client->printPrompt() if ($printed);

	return 1;
}

sub download
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $localFolder;
	my $idx;

	if ($argc < 3)
	{
		$client->writeConsoleOutput(text =>
				"Usage: download src1 [src2 ...] dst\n");
		goto out;
	}
	
	$localFolder = $argv[$argc - 1];

	# Enumerate through all of the download files
	for ($idx = 1; 
	     $idx < $argc - 1; 
	     $idx++)
	{
		my $handlerParameter = {};
		my $remoteFileName = $argv[$idx];
		my $localFile;

		$remoteFileName =~ s/.*[\\\/](.*?)$/$1/;
		$localFile      = $localFolder . "/" . $remoteFileName;

		# Initialize the handler parameter hash
		$handlerParameter->{'file'} = $localFile;
		$handlerParameter->{'fd'}   = undef;

		$client->writeConsoleOutput(text =>
				"download: Starting download from '" . $argv[$idx] . "' to '" . $localFile . "'...\n");

		# Open the file for read
		openFile(
				client                     => $client,
				remoteFile                 => $argv[$idx],
				mode                       => Def::FILE_MODE_READ,
				completionHandler          => \&downloadOpenComplete,
				completionHandlerParameter => $handlerParameter);
	}

	$client->writeConsoleOutput(text =>
			"download: " . ($idx - 1) . " downloads started.\n");

out:
	return 1;
}

##
#
# Utility methods
#
##

#
# Opens a file on the remote endpoint
#
sub openFile
{
	my ($client, $remoteFile, $mode, $completionHandler, $completionHandlerParameter) = @{{@_}}{qw/client remoteFile mode completionHandler completionHandlerParameter/};
	my @tlvs = 
	(
		{
			type  => Def::TLV_TYPE_METHOD,
			value => "core_channel_open"
		},
		{
			type  => Def::TLV_TYPE_FS_PATH,
			value => $remoteFile,
		},
		{
			type  => Def::TLV_TYPE_FS_MODE,
			value => $mode,
		},
		{
			type  => Def::TLV_TYPE_CHANNEL_TYPE,
			value => "fs",
		},
	);

	# Call open
	return Pex::Meterpreter::Channel::open(
			client                     => $client,
			addends                    => \@tlvs,
			completionHandler          => $completionHandler,
			completionHandlerParameter => $completionHandlerParameter);
}

1;
