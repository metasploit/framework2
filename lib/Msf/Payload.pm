
###############

##
#         Name: Payload.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#  Description: Parent class for Payloads, inherits from Module.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::Payload;
use strict;
use base 'Msf::Module';

my $defaults =
{
  'Multistage'  => 0,
  'Type'        => '',
  'Size'        => 0,
  'Append'      => '',
  'Prepend'     => '',
  'PrependEncoder'  => '',  
  'BadChars'    => '',
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash->{'_InfoDefaults'} = $defaults;
  my $self = $class->SUPER::new($hash);
  return($self);
}

sub _Load {
}

sub Type        { my $self = shift; return $self->_Info->{'Type'}; }
sub Size        { my $self = shift; return $self->_Info->{'Size'}; }
sub Multistage  { my $self = shift; return $self->_Info->{'Multistage'}; }
sub BadChars    { my $self = shift; return $self->_Info->{'BadChars'}; }

sub Loadable {
  my $self = shift;
  return($self->Size > 0);
}

# Fall throughs
sub Build {
  my $self = shift;
  return($self->Generate);
}

sub Generate {
  my $self = shift;
  $self->PrintLine('[*] No Generate for this payload: ' , $self->SelfName);
  return;
}

#
# Substitutes variable offsets (if defined) with values from the environment.
#
sub SubstituteVariables # (self, hash, payload)
{
	my $self = shift;
	my $hash = shift;
	my $payload = shift;
	my $opts = $hash->{'Offsets'};

	# If there are offsets...
	if (defined($opts))
	{
		# Enumerate through all of the options
		foreach my $opt (keys(%{ $opts }))
		{
			my ($offset, $pack) = @{ $hash->{'Offsets'}->{$opt} };
			my $type = $opts->{$opt}->[1];
			my $value;

			$self->PrintDebugLine(3, "Payload: searching for opt=$opt type=$type");
	
			# Allow derived classes the chance to replace advanced variables such
			# as EXITFUNC for win32
			next if (defined($self->ReplaceVariable(
					hash    => $hash,
					payload => \$payload,
					option  => $opt, 
					offset  => $offset,
					packing => $pack)));
				
			# If there is a corresponding environment variable for the option...
			if ((defined($value = $self->GetVar($opt))) or
			    (defined($value = $self->GetLocal($opt))))
			{
				$self->PrintDebugLine(3, "Payload: replacing opt=$opt type=$type value=$value");
	
				if ($type eq 'ADDR')
				{
					$value = gethostbyname($value)
				}
				elsif ($type eq 'RAW')
				{
					# Just use whatever we were given
				}
				else
				{
					$value = pack($pack, $value);
				}
				
				# Replace with the value at the supplied offset for this variable
				substr($payload, $offset, length($value), $value);
			}
			else
			{
				$self->PrintDebugLine(3, "Payload: not replacing opt=$opt type=$type");	
			}
		}
	}

	return $payload;
}

#
# Stub for replacing variables that can be overriden by derived classes
#
sub ReplaceVariable
{
	return undef;
}

1;
