
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::JmpCallAdditive;
use strict;
use base 'Msf::Encoder';
use Pex::Encoding::XorDwordFeedback;

my $advanced = {
};

my $info = {
	'Name'    => 'IA32 Jmp/Call XOR Additive Feedback Decoder',
	'Version' => '$Revision$',
	'Authors' =>
		[
			'skape <mmiller [at] hick.org>'
		],
	'Arch'    => [ 'x86' ],
	'OS'      => [ ],
	'Description'  =>  'Jmp/Call XOR Additive Feedback Decoder',
	'Refs'    => [ ],
};

sub new 
{
	my $class = shift; 

	return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

sub EncodePayload 
{
	my $self = shift;
	my $payload = shift;
	my $badchars = shift;
	my $shellcode;
	my $encoded;
	my $pos;
	my $key;

	my $decoder =
		"\xfc" .                # cld
		"\xbbXORK" .            # mov ebx, key
		"\xeb\x0c" .            # jmp short 0x14
		"\x5e" .                # pop esi
		"\x56" .                # push esi
		"\x31\x1e" .            # xor [esi], ebx
		"\xad" .                # lodsd
		"\x01\xc3" .            # add ebx, eax
		"\x85\xc0" .            # test eax, eax
		"\x75\xf7" .            # jnz 0xa
		"\xc3" .                # ret
		"\xe8\xef\xff\xff\xff"; # call 0x8

	if (not defined($key = Pex::Encoding::XorDwordFeedback->KeyScan($payload, $badchars)))
	{
		$self->PrintDebugLine(3, "Failed to find XOR key");
		return undef;
	}

	$shellcode =  $decoder . $self->EncodeXorDwordAdditive($key, $payload);
	$key       =  pack("V", $key);
	$shellcode =~ s/XORK/$key/s;

	if (($pos = Pex::Text::BadCharIndex($badchars, $shellcode)) != -1)
	{
		$self->PrintDebugLine(3, "Bad character found at $pos");
		return undef;
	}

	return $shellcode;
}

sub EncodeXorDwordAdditive
{
	my $self = shift;
	my $key = shift;
	my $payload = shift;
	my $encoded = '';
	my $length = length($payload);
	my $offset;
	my $orig;

	for ($offset = 0; $offset < $length; $offset+=4)
	{
		my $chunk = substr($payload, $offset, 4);

		$chunk   .= "\x00" x (4 - length($chunk));
		$orig     = unpack("V", $chunk);
		$chunk    = unpack("V", $chunk) ^ $key;
		$encoded .= pack("V", $chunk);
		$key      = Pex::Utils::DwordAdd($key, $orig);
	}

	$encoded .= pack("V", $key);

	return $encoded;
}

1;
