###############
##
#         Name: Win32Payload.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#  Description: Parent class for win32 payloads, supports multiple process
#               exit methods, etc. Inherits from Payload.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##
###############

package Msf::PayloadComponent::Windows::Payload;
use strict;
use base 'Msf::Payload';
use Pex::Utils;
use vars qw{@ISA};

my $exitTypes = 
{ 
	"process" => Pex::Utils::RorHash("ExitProcess"),
	"thread"  => Pex::Utils::RorHash("ExitThread"),
	"seh"     => Pex::Utils::RorHash("SetUnhandledExceptionFilter"),
};

#
# Dynamically inherit from the provided base classes at runtime
#
sub _Import
{
	my $class = shift;

	@ISA = ( 'Msf::Payload' );

	foreach (@_)
	{
		eval("use $_");
		unshift(@ISA, $_);
	}
}

sub new 
{
	my $class = shift;
	my $hash = @_ ? shift : { };
	my $self = $class->SUPER::new($hash);

	$self->InitWin32;

	return($self);
}

#
# Initialize defaults
#
sub InitWin32 
{
	my $self = shift;

	$self->{'Info'}->{'UserOpts'}->{'EXITFUNC'} = [1, 'DATA', 'Exit technique: "process", "thread", "seh"', 'seh'];
}

#
# Return the payload hash
#
sub Payload
{
	my $self = shift;

	return $self->_Info->{'Payload'};
}

#
# Calculate the payload size
#
sub Size 
{
	my $self = shift;
	my $size = length($self->Build);

	$self->PrintDebugLine(3, "Win32Payload: returning Size of $size");
	$self->PrintDebugLine(5, "Win32Payload: size on $self");

	return $size;
}

#
# Build out the payload and substitute variables
#
sub Build
{
	my $self = shift;

	return $self->BuildPayload($self->Payload);
}

#
# Build a specific payload and substitute variables
#
sub BuildPayload
{
	my $self = shift;
	my $hash = shift;
	my $payload;

	$payload = $self->SubstituteVariables(
			$hash,
			$hash->{'Payload'});

	# FIXME: Temporary hack - make sure the direction bit is not set.
	return $payload;
}

#
# Replace win32 specific variables such as EXITFUNC.  This function is
# called back via calls to SubstituteVariables.
#
sub ReplaceVariable
{
	my $self = shift;
	my ($hash, $payload, $option, $offset, $packing) = @{{@_}}{qw/hash payload option offset packing/};
	my $replaced = undef;

	#
	# Replace the exit function
	#
	if ($option eq 'EXITFUNC')
	{
		if ($offset > 0)
		{
			my $func = ($self->GetVar('EXITFUNC')) ? $self->GetVar('EXITFUNC') : 'seh';
			my $hash = exists($exitTypes->{$func}) ? $exitTypes->{$func} : $exitTypes->{'seh'};

			substr($$payload, $offset, 4, pack('V', $hash));

			$replaced = 1;
		}
	}

	return $replaced;
}

1;
