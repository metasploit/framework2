##
# This file is part of the Metasploit Framework and may be redistributed according
# to the licenses defined in the Authors fields below. In the case of a an Unknown
# license, this file defaults to using the same license as the core Framework. The
# latest version of the Framework can always be obtained from http://metasploit.com
##

package Msf::Payload::Empty;
use strict;
use base 'Msf::PayloadComponent::NoConnection';

my $info =
{
  'Name'         => 'Empty',
  'Version'      => '$Revision$',
  'Description'  => 'Empty payload (for testing)',
  'Authors'      => [ 'spoonm <ninjatools [at] hush.com>', ],
  'Priv'         => 0,
  'Size'         => 0,
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

# bypass the size > 0 check
sub Loadable {
  my $self = shift;
  return($self->DebugLevel > 0);
}

sub Build {
  my $self = shift;
  return('');
}

1;
