###############
##
#
#    Name: Payload.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      Payload base class for OSX.
#
##
###############

package Msf::PayloadComponent::OSX::Payload;

use strict;
use base 'Msf::Payload';
use vars qw{@ISA};

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
	my $hash  = @_ ? shift : { };
	my $self  = $class->SUPER::new($hash);

	return $self;
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
	
	return length($self->Build);
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

	return $payload;
}

1;
