
###############
##
#
#    Name: LocalDispatch.pm
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
#      This module implements the base input handlers for the console.
#
##
###############

package Pex::Meterpreter::LocalDispatch;

use strict;
use FindBin qw($RealBin);
use Pex::Meterpreter::Arguments;
use Pex::Meterpreter::Buffer;
use Pex::Meterpreter::Packet;

#
# Registers all of the input handlers
#
sub registerHandlers
{
	my ($client) = @{{@_}}{qw/client/};
	my @handlers = (
		{
			identifier  => "Core",
			description => "Core feature set commands",
			handler     => undef,
		},
		{
			identifier  => "read",
			description => "Reads from a communication channel",
			handler     => \&Pex::Meterpreter::LocalDispatch::read,
		},
		{
			identifier  => "write",
			description => "Writes to a communication channel",
			handler     => \&Pex::Meterpreter::LocalDispatch::write,
		},
		{
			identifier  => "close",
			description => "Closes a communication channel",
			handler     => \&Pex::Meterpreter::LocalDispatch::close,
		},
		{
			identifier  => "interact",
			description => "Switch to interactive mode with a channel",
			handler     => \&Pex::Meterpreter::LocalDispatch::interact,
		},
		{
			identifier  => "help",
			description => "Displays the list of all register commands",
			handler     => \&Pex::Meterpreter::LocalDispatch::help,
		},
		{
			identifier  => "exit",
			description => "Exits the client",
			handler     => \&Pex::Meterpreter::LocalDispatch::exit,
		},
		{
			identifier  => "initcrypt",
			description => "Initializes the cryptographic subsystem",
			handler     => \&Pex::Meterpreter::LocalDispatch::initcrypt,
		},
		{
			identifier  => "Extensions",
			description => "Feature extension commands",
			handler     => undef,
		},
		{
			identifier  => "loadlib",
			description => "Loads a library on the remote endpoint",
			handler     => \&Pex::Meterpreter::LocalDispatch::loadlib,
		},
		{
			identifier  => "use",
			description => "Uses a feature extension module",
			handler     => \&Pex::Meterpreter::LocalDispatch::use,
		},
	);

	# Enumerate through all of the handlers adding them.
	foreach my $handler (@handlers)
	{
		$client->registerLocalInputHandler(
				identifier  => $handler->{'identifier'},
				description => $handler->{'description'},
				handler     => $handler->{'handler'});
	}

	return 1;
}

##
#
# The handlers themselves.
#
##

#
# Reads from a channel
#
sub readComplete
{
	my ($channel, $client, $result, $buffer, $length) = @{{@_}}{qw/channel client result buffer length/};
	
	if ($result == 0)
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"read: Read $length bytes from channel " . $$channel->getId() . ":\n\n$buffer\n");
	}
	else
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"read: Failed to read from channel, $result.\n");
	}
	
	$client->printPrompt();

	return 1;
}

sub read
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $channelId;
	my $channel;
	my $length = 8192;

	# Validate arguments
	if ($argc == 1)
	{
		$client->writeConsoleOutput(text => 
				"Usage: read channel_id [length]\n");
		goto out;
	}

	$channelId = $argv[1];
	$length    = $argv[2] if ($argc >= 3);

	# Check to make sure that the channel identifier is valid
	if (not defined($channel = Pex::Meterpreter::Channel::find(
			id => $channelId)))
	{
		$client->writeConsoleOutput(text =>
				"Error: The channel identifier $channelId is invalid.\n");
		goto out;
	}

	$client->writeConsoleOutput(text =>
			"read: Reading $length bytes from channel $channelId...\n");

	# Perform the read operation
	$$channel->read(
			client            => $client,
			length            => $length,
			completionHandler => \&readComplete);

out:
	return 1;
}

#
# Writes to a channel
#
sub writeComplete
{
	my ($channel, $result, $client, $length, $ctx) = @{{@_}}{qw/channel result client length handlerParameter/};

	if ($result == 0)
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"write: Successfully wrote $length bytes to channel " . $$channel->getId() . "\n");
	}
	else
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"write: Failed to write to channel " . $$channel->getId() . "\n");
	}

	$client->printPrompt();

	return 1;
}

sub write
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $channelId;
	my $channel;
	my $buf = '';

	# Validate arguments
	if ($argc == 1)
	{
		$client->writeConsoleOutput(text => 
				"Usage: write channel_id\n");
		goto out;
	}

	$channelId = $argv[1];

	# Check to make sure that the channel identifier is valid
	if (not defined($channel = Pex::Meterpreter::Channel::find(
			id => $channelId)))
	{
		$client->writeConsoleOutput(text =>
				"Error: The channel identifier $channelId is invalid.\n");
		goto out;
	}

	# Read input off the console
	my $input = $client->getConsoleInput();

	$client->writeConsoleOutput(text =>
			"write: Enter text terminated with single-line '.':\n\n");

	while (<$input>)
	{	
		last if (substr($_, 0, 1) eq '.' and length($_) <= 3);

		$buf .= $_;	
	}

	# Make sure that some text was provided
	if (length($buf) == 0)
	{
		$client->writeConsoleOutput(text =>
				"Error: No input was provided.\n");
		last;
	}

	# Write to the remote endpoint
	$$channel->write(
			client            => $client,
			buffer            => $buf,
			completionHandler => \&writeComplete);

out:
	return 1;
}

#
# Close a channel
#
sub close
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $channelId;
	my $channel;
	my $buf = '';

	# Validate arguments
	if ($argc == 1)
	{
		$client->writeConsoleOutput(text => 
				"Usage: close channel_id\n");
		goto out;
	}

	$channelId = $argv[1];

	# Check to make sure that the channel identifier is valid
	if (not defined($channel = Pex::Meterpreter::Channel::find(
			id => $channelId)))
	{
		$client->writeConsoleOutput(text =>
				"Error: The channel identifier $channelId is invalid.\n");
		goto out;
	}

	$client->writeConsoleOutput(text =>
			"close: Closing channel $channelId...\n");

	# Close the channel
	$$channel->close(
			client => $client);

out:
	return 1;
}

#
# Switch to an interactive channel
#
sub interactComplete
{
	my ($channel, $client, $result) = @{{@_}}{qw/channel client result/};

	if ($result == 0)
	{
		my $channelId = $$channel->getId();

		$client->writeConsoleOutput(text =>
				"\n" .
				"interact: Started interactive channel $channelId.\n\n");

		# Override the interact channel
		$client->setInteractiveChannel(channel => $channel);
	}
	else
	{
		$client->writeConsoleOutput(text =>
				"interact: Failed to start interactive channel, $result.\n");
	}
}

sub interact
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $channelId;
	my $channel;

	# Validate arguments
	if ($argc == 1)
	{
		$client->writeConsoleOutput(text => 
				"Usage: interact channel_id\n");
		goto out;
	}

	$channelId = $argv[1];

	# Check to make sure that the channel identifier is valid
	if (not defined($channel = Pex::Meterpreter::Channel::find(
			id => $channelId)))
	{
		$client->writeConsoleOutput(text =>
				"Error: The channel identifier $channelId is invalid.\n");
		goto out;
	}

	$client->writeConsoleOutput(text =>
			"interact: Switching to interactive console on $channelId...\n");

	# Call interact on the channel
	$$channel->interact(
			client            => $client,
			enable            => 1,
			completionHandler => \&interactComplete);

out:

	return 1;
}

#
# Provide a help menu with all of the registered console commands
#
sub help
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my $index = 0;
	my $handler;
	my $buf;

	while (defined($handler = $client->enumerateLocalInputHandlers(
			index => $index++)))
	{
		if (not defined($handler->{'handler'}))
		{
			$buf = sprintf(
					"\n" .
					"%13s   %s\n" .
					" ------------   ----------------\n", 
					$handler->{'identifier'}, $handler->{'description'});
		
		}
		else
		{
			$buf = sprintf(
					"%13s   %s\n",
					$handler->{'identifier'}, $handler->{'description'});

		}

		$client->writeConsoleOutput(text => $buf);
	}

	return 1;
}

#
# Exit the client
#
sub exit
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @arguments = @{ $argumentsScalar };

	print $console "exit\n";

	return -1;
}

#
# Initialize a cryptographic connection with the remote endpoint
#
sub initcrypt
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $initializer;
	my $banner = 1;
	my $res;

	goto out if ($argc == 1);

	$initializer = join(" ", @argv[2 .. @argv - 1]) if ($argc > 2);

	$banner = 0;

	# Set the cryptographic cipher on the client context
	$res = $client->setCipher(
			cipher      => $argv[1],
			initializer => $initializer);

	if ($res <= 0)
	{
		$client->writeConsoleOutput(text =>
				"Error: Failed to initialize the provided cryptographic subsystem.\n");
		goto out;
	}

	$client->writeConsoleOutput(text =>
			"initcrypt: Using cryptographic cipher: " . $argv[1] . "\n");

out:
	if ($banner)
	{
		$client->writeConsoleOutput(text =>
				"Usage: initcrypt cipher [parameters]\n" .
				"  Supported Ciphers: xor\n");
	}

	return 1;
}

#
# Loads a library in the context of the process on the remote endpoint
#
sub loadlibComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};

	return $client->writeConsoleOutputResponse(
			cmd    => 'loadlib',
			packet => $packet);
}

sub loadlib
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my $argc   = scalar(@{ $argumentsScalar });
	my $parser = Pex::Meterpreter::Arguments->new(
			argv => $argumentsScalar, 
			fmt  => 'f:t:lde');
	my $banner = 1;
	my $toggle = 0;
	my $libraryPath;
	my $targetPath;
	my $request;
	my $flags = Def::LOAD_LIBRARY_FLAG_LOCAL;

	# Break out if no arguments are supplied
	goto out if ($argc == 1);

	# Enumerate the command line arguments
	while (defined($toggle = $parser->parse()))
	{
		if ($toggle eq 'f')
		{
			$libraryPath = $parser->getArgument();
		} 
		elsif ($toggle eq 't')
		{
			$targetPath = $parser->getArgument();
		}
		elsif ($toggle eq 'l')
		{
			$flags &= ~(Def::LOAD_LIBRARY_FLAG_LOCAL);
		}
		elsif ($toggle eq 'd')
		{
			$flags |= Def::LOAD_LIBRARY_FLAG_ON_DISK;
		}
		elsif ($toggle eq 'e')
		{
			$flags |= Def::LOAD_LIBRARY_FLAG_EXTENSION;
		}
	}

	# Set the target path to the library path if it's not defined
	$targetPath = $libraryPath if (not defined($targetPath));

	# Validate the arguments
	if (not defined($libraryPath))
	{
		$client->writeConsoleOutput(text =>
				"Error: No library path was specified.\n");
		goto out;
	}

	$banner = 0;

	# Create the packet
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST, 
			method => "core_loadlib");

	# If the library is not local to the remote machine, upload it.  This entails
	# serializing the local library to a buffer and transmitting it as part of
	# the request.
	if (!($flags & Def::LOAD_LIBRARY_FLAG_LOCAL))
	{
		my $buffer = Pex::Meterpreter::Buffer->new(
				filePath => $libraryPath);

		if ($buffer)
		{
			$request->addTlv(
					type  => Def::TLV_TYPE_DATA,
					value => $buffer->getData());
		}
		else
		{
			$client->writeConsoleOutput(text => 
					"Error: The local library path could not be serialized.\n");
			goto out;
		}

		# Change the name of the library as it no longer means anything to the
		# remote machine.
		$libraryPath = "ext" . int(rand(1000000)) . ".dll";
		$targetPath  = $libraryPath;
	}

	# Add TLVs
	$request->addTlv(
			type  => Def::TLV_TYPE_LIBRARY_PATH,
			value => $libraryPath);
	$request->addTlv(
			type  => Def::TLV_TYPE_FLAGS,
			value => $flags);
	
	if (defined($targetPath))
	{
		$request->addTlv(
				type  => Def::TLV_TYPE_TARGET_PATH,
				value => $targetPath);
	}

	$client->writeConsoleOutput(text => 
			"loadlib: Loading library from '$libraryPath' on the remote machine.\n");

	# Transmit the packet
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&loadlibComplete);

out:
	# If banner is set, we shall print help
	if ($banner)
	{
		$client->writeConsoleOutput(text => 
				"Usage: loadlib -f library [ -t target ] [ -lde ]\n\n" .
				"  -f <file>  The path to the library to load, whether local or remote.\n" .
				"  -t <targ>  The target file on the remote machine in which to store the library when uploading.\n" .
				"  -l         The library is local to the client machine, upload it to the remote machine.\n" .
				"  -d         When used with -l, this parameter indicates that the library should be saved to disk.\n" .
				"  -e         The library being loaded is a feature extension module, call its Init routine on load.\n");
	}

	return 1;
}

#
# Uses a feature module, causing the respective client and server modules to
# be loaded.
#
# TODO
#
#   - Make this OS independent (file paths, server module extension, etc...)
#
sub use
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my $argc   = scalar(@{ $argumentsScalar });
	my $parser = Pex::Meterpreter::Arguments->new(
			argv => $argumentsScalar, 
			fmt  => 'm:p:d');
	my $banner = 1;
	my $toggle = 0;
	my @loadlibArgv;
	my $diskOnly = 0;
	my $modules;
	my $path = $RealBin . "/data/meterpreter";

	# If no arguments are supplied, print the banner.
	goto out if ($argc == 1);

	# Parse the arguments
	while (defined($toggle = $parser->parse()))
	{
		if ($toggle eq 'm')
		{
			$modules = $parser->getArgument();
		}
		elsif ($toggle eq 'p')
		{
			$path = $parser->getArgument();
		}
		elsif ($toggle eq 'd')
		{
			$diskOnly = 1;
		}
	}

	# No module?
	if (not defined($modules))
	{
		$client->writeConsoleOutput(text =>
				"Error: You must specify at least one module.\n");
		goto out;
	}

	$banner = 0;

	# Fix the path
	$path .= '/';

	# Enumerate the module list
	foreach my $module (split /,/, $modules)
	{
		my $clientExtension;
		my $clientPath;
		my $serverPath;
		my $skip = 0;

		# Check to see if the module is already loaded
		foreach my $exists (@{ $client->{'modules'} })
		{
			if (lc($exists) eq lc($module))
			{
				$client->writeConsoleOutput(text =>
						"Error: The module '$module' is already loaded.\n");

				$skip = 1;

				last;
			}
		}

		next if ($skip);

		# Load the client module
		$clientPath  = "Pex::Meterpreter::Extension::Client::$module";

		eval '
			require ' . $clientPath . ';

			$clientExtension = ' . $clientPath . '->new(client => $client);
			';

		if (not defined($clientExtension))
		{
			$client->writeConsoleOutput(text =>
					"Error: The client extension '$module' could not be loaded.\n");
			last;
		}

		# Push the module into the loaded module list
		push @{ $client->{'modules'} }, $module;

		# Load the server module
		$serverPath  = $path . "ext_server_" . lc($module) . ".dll";
		$serverPath =~ s/\/\//\//;
		@loadlibArgv = ();	

		# Build the loadlib argument vector
		push (@loadlibArgv, "loadlib");
		push (@loadlibArgv, "-f");
		push (@loadlibArgv, $serverPath);
		push (@loadlibArgv, "-e");
		push (@loadlibArgv, "-l");
		push (@loadlibArgv, "-d") if ($diskOnly);

		# Call loadlib
		Pex::Meterpreter::LocalDispatch::loadlib(
				client    => $client,
				console   => $console,
				parameter => \@loadlibArgv);
	}

out:
	# Display the banner if necessary
	if ($banner)
	{
		$client->writeConsoleOutput(text =>
				"Usage: use -m module1,module2,module3 [ -p path ] [ -d ]\n\n" .
				"  -m <mod>   The names of one or more modules to load (e.g. 'net').\n" .
				"  -p <path>  The path to load the modules from locally.\n" .
				"  -d         Load the library from disk, do not upload it.\n");
	}

	return 1;
}

1;
