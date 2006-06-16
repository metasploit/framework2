
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::cmd_localshell;
use strict;
use base 'Msf::PayloadComponent::FindLocalShell';

my $info =
{
  'Name'         => 'Interactive Local Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Interact with a standard shell',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com>', ],
  'Priv'         => 0,
  'OS'           => [  ],
  'Keys'        => ['+cmd_localshell'],
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);

  # This has to be non-zero for the Loadable check to function
  $self->_Info->{'Size'} = 1;
  return($self);
}

sub Build { return }

1;
