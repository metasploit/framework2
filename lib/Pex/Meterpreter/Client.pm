
###############
##
#
#    Name: Client.pm
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
#      This module implements the meterpreter client, including
#      console interaction.
#
##
###############

package Pex::Meterpreter::Client;

use strict;
use IO::Select;

use Pex::Meterpreter::Base;
use Pex::Meterpreter::Packet;

# Cryptographic ciphers
use Pex::Meterpreter::Crypto::Xor;

our @ISA = qw( Pex::Meterpreter::Base );

#
# Constructor
#
sub new
{
	my $this  = shift;
	my $class = ref($this) || $this;
	my $self  = {};
	my ($consoleIn, $consoleOut, $socketIn, $socketOut) = @{{@_}}{qw/consoleIn consoleOut socketIn socketOut/};

	bless($self, $class);

	# Initialize base classes
	Pex::Meterpreter::Base->new(self => $self);

	# Initialize class attributes
	$self->{'socketIn'}           = $socketIn;
	$self->{'socketOut'}          = $socketOut;
	$self->{'consoleIn'}          = $consoleIn;
	$self->{'consoleOut'}         = $consoleOut;

	$self->{'interactiveChannel'} = undef;

	# Selectables
	$self->{'selector'}           = IO::Select->new;
	$self->{'selectables'}        = {};

	# Modules list
	$self->{'modules'}            = ();

	return $self;
}

#
# Process data from the console and from the socket, dispatching
# them to the appropriate handlers
#
# Some of the logic taken from TextConsole
#
sub run
{
	my $self = shift;
	my $oldSigint;
	my $loop = 1;
	my $select;
	my $res;

	# Overwrite sigint handler
	my $sigintHandler = sub 
	{	
		my $interactive = $self->getInteractiveChannel();
		my $question;
		my $yes = 0;

		# If there is an interactive channel, prompt the user accordingly
		if (defined($interactive))
		{
			$question = "Caught interrupt, close interactive session? [y/N] ";
		}
		else
		{
			$question = "Caught interrupt, abort meterpreter? [y/N] ";
		}

		$self->getConsoleOutput->printflush($question);

		my $fd = $self->getConsoleInput;
		$fd->blocking(0);
					
		my $start = time();
		while ($start + 30 > time()) {
	
			my $answer = $fd->getline;		
			if (! $answer) {
				select(undef, undef, undef, 0.5);
				next;
			}
			
			next if $answer eq "!^! MSF_INTERRUPT\n";
			
			if (lc($answer) =~ /^y/) {
				$yes = 1;
				last;
			}
			elsif (lc($answer) =~ /^n/) {
				last;
			}
			
			$self->getConsoleOutput->printflush($question);
		}
		
		$fd->blocking(1);		
		
		# If the user answers yes, either stop interacting with the channel or set
		# the loop flag to 0
		if ($yes)
		{
			if (defined($interactive))
			{
				$$interactive->interact(
						client => $self,
						enable => 0);
			}
			else
			{
				$loop = 0;
			}
		}
	};

	$oldSigint  = $SIG{'INT'};
	$SIG{'INT'} = $sigintHandler;

	# Make all fd's blocking
	foreach my $fd (
		$self->getSocketInput(), 
		$self->getSocketOutput(),
		$self->getConsoleInput(),
		$self->getConsoleOutput())
	{
		$fd->blocking(1);
		$fd->autoflush(1);
	}

	# Add the console input and socket input selectables
	$self->addSelectable(
			handle        => $self->getConsoleInput(),
			notifyHandler => \&processConsoleInput);
	$self->addSelectable(
			handle        => $self->getSocketInput(),
			notifyHandler => \&processSocketInput);

	# Print the initial prompt
	$self->printPrompt();

	# Loop until told not to
	while ($loop)
	{
		my @readable = $self->{'selector'}->can_read(2);

		foreach my $fd (@readable)
		{
			next if ! $loop;
			my $handler = $self->{'selectables'}->{$fd}->{'notifyHandler'};

			if (defined($handler))
			{
				$res = &{ $handler }(
						client  => $self,
						context => $self->{'selectables'}->{$fd}->{'notifyHandlerParameter'});
			}

			$loop = 0 if ($res < 0);
		}

		# No longer connected?
		last if (!$self->getSocketOutput()->connected);
	}

	# Restore sigint handler
	$SIG{'INT'} = $oldSigint;
	
	$self->getConsoleOutput->printflush("The meterpreter is shutting down...\n");
	return;
}

#
# Process input from the socket
#
sub processSocketInput
{
	my ($self) = @{{@_}}{qw/client/};
	my $currentPacket;
	my $res;

	# If no packet context has been allocated, do so now.
	if (not defined($self->{'currentPacket'}))
	{
		$self->{'currentPacket'} = Pex::Meterpreter::Packet->new;
	}

	$currentPacket = $self->{'currentPacket'};

	# Read in from the socket
	$res = $currentPacket->recv(
			fd     => $self->getSocketInput(),
			cipher => $self->getCipher());

	# If recv returns true, a full packet has been read in and we can now
	# process it.
	if ($res > 0)
	{
		$self->dispatchRemotePacket(packet => \$currentPacket);

		$self->{'currentPacket'} = undef;
	}

	return $res;
}

#
# Process input from the console
#
sub processConsoleInput
{
	my ($self) = @{{@_}}{qw/client/};
	my $consoleIn;
	my $consoleOut;
	my $res = 1;
	my $chan;
	my $cmd;

	$consoleIn  = $self->getConsoleInput();
	$cmd        = $consoleIn->getline;

	# If a valid command is supplied, dispatch it for processing
	if (defined($cmd))
	{

		# Check for the magic interrupt and shutdown requests
		if ($cmd eq "!^! MSF_SHUTDOWN\n") {
			return -1;
		}
		if ($cmd eq "!^! MSF_INTERRUPT\n") {
			kill INT => $$;
			return $res;
		}

		# If an interactive channel is supplied, write the input buffer to it,
		# otherwise process the command locally
		if (defined($chan = $self->getInteractiveChannel()))
		{
			$$chan->write(
					client => $self,
					buffer => $cmd);
		}
		else
		{
			chomp($cmd);

			$res = $self->dispatchLocalInput(command => $cmd);

			$self->printPrompt() if ($res >= 0);
		}
	}

	return $res;
}

#
# Print the meterpreter prompt
#
sub printPrompt
{
	my $self = shift;
	my $consoleOut = $self->getConsoleOutput();

	print $consoleOut $self->getPrompt();
}

#
# Clears the console output line -- in reality, this should blank the current
# line instead of simply using a new line.
#
sub clearConsoleOutputLine
{
	my $self = shift;
	my $console = $self->getConsoleOutput();

	print $console "\n";
}

#
# Writes the supplied text to the output console
#
sub writeConsoleOutput
{
	my $self = shift;
	my ($text) = @{{@_}}{qw/text/};
	my $console = $self->getConsoleOutput();

	print $console $text;
}

#
# Writes generic console output for the contents of a given message
#
sub writeConsoleOutputResponse
{
	my $self = shift;
	my ($cmd, $packet) = @{{@_}}{qw/cmd packet/};
	my $console = $self->getConsoleOutput();
	my $result;

	my $result = $$packet->getResult();

	$cmd = "notice" if (not defined($cmd));

	$self->clearConsoleOutputLine();

	if ($result == 0)
	{
		$self->writeConsoleOutput(text => 
				"$cmd: success.\n");
	}
	else
	{
		$self->writeConsoleOutput(text => 
				"$cmd: failure, $result.\n");
	}

	$self->printPrompt();
}

##
#
# Getters/Setters
#
##

#
# Get the socket input handle
#
sub getSocketInput
{
	my $self = shift;

	return $self->{'socketIn'};
}

#
# Get the socket output handle
#
sub getSocketOutput
{
	my $self = shift;

	return $self->{'socketOut'};
}

#
# Get the console input handle
#
sub getConsoleInput
{
	my $self = shift;

	return $self->{'consoleIn'};
}

#
# Get the console output handle
#
sub getConsoleOutput
{
	my $self = shift;

	return $self->{'consoleOut'};
}

#
# Returns the prompt string for console input
#
sub getPrompt
{
	return "meterpreter> ";
}

#
# Returns the file delimiter of the remote endpoint based on platform.
# Currently meterpreter only supports win32, so this just returns '\'
#
sub getRemoteFileDelimiter
{
	return "\\";
}

#
# Sets the channel that is interactive
#
sub setInteractiveChannel
{
	my $self = shift;
	my ($channel) = @{{@_}}{qw/channel/};

	$self->{'interactiveChannel'} = $channel;
}

#
# Returns the interactive channel, if any
#
sub getInteractiveChannel
{
	my $self = shift;

	return $self->{'interactiveChannel'};
}

##
#
# Selectables
#
##

#
# Create a new selectable that will be polled in the main select loop
#
sub addSelectable
{
	my $self = shift;
	my ($handle, $notifyHandler, $notifyHandlerParameter) = @{{@_}}{qw/handle notifyHandler notifyHandlerParameter/};

	$self->{'selectables'}->{$handle}                             = {};
	$self->{'selectables'}->{$handle}->{'notifyHandler'}          = $notifyHandler;
	$self->{'selectables'}->{$handle}->{'notifyHandlerParameter'} = $notifyHandlerParameter;

	$self->{'selector'}->add($handle);
}

#
# Remove a previuosly added selectable
#
sub removeSelectable
{
	my $self = shift;
	my ($handle) = @{{@_}}{qw/handle/};

	$self->{'selector'}->remove($handle);

	delete $self->{'selectables'}->{$handle};
}

##
#
# Cryptography
#
##

#
# Sets the cipher context that is to be used when transmitting and receiving
# packets.
#
sub setCipher
{
	my $self = shift;
	my ($cipher, $initializer) = @{{@_}}{qw/cipher initializer/};
	my @ciphers = ("xor");
	my $inst;

	# Instantiate the cipher
	if ($cipher eq "xor")
	{
		$inst = Pex::Meterpreter::Crypto::Xor->new(
				initializer => $initializer);
	}

	# Update the client's cipher context
	$self->{'cipher'} = \$inst;

	# If this is a valid instance, transmit an initialization request to the
	# remote endpoint
	if (defined($inst))
	{
		my $request = Pex::Meterpreter::Packet->new(
				type   => Def::PACKET_TYPE_PLAIN_REQUEST,
				method => "core_crypto_negotiate");

		# Allow the underlying cipher to append information to the negotiation
		# request
		$inst->populateNegotiateRequest(
				packet => \$request);

		# Transmit the request
		$self->transmitPacket(
				packet => \$request);
	}

	return (defined($inst)) ? 1 : 0;
}

#
# Gets the cipher context that has been set on the client, if any
#
sub getCipher
{
	my $self = shift;

	return $self->{'cipher'};
}

1;
