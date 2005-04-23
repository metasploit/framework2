
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Nop::PPC;
use strict;
use base 'Msf::Nop';
use Pex::Utils;

my $info = {
  'Name'    => 'PPC Nop Generator',
  'Version' => '$Revision$',
  'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],
  'Arch'    => [ 'ppc' ],
  'Desc'    =>  'This is a simple PPC nop generator',
  'Refs'    => [ ],
};

my $advanced = { };

sub new {
  my $class = shift; 
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

sub Nops {
	my $self = shift;
	my $length = shift;

	my $exploit = $self->GetVar('_Exploit');
	my $random  = $self->GetVar('RandomNops');
	my $badChars = $exploit->PayloadBadChars;

	if ($random) {
		
		# Extremely simple "add" instruction generator
		for (1 .. 1024) {		
			# Ignore target registers r0 or r1
			my $regs_d = int(rand() * (0x8000 - 0x0800)) + 0x0800;
			my $regs_b = substr(unpack("B*", pack("n", $regs_d)), 1, 15);
			my $flag_o = int(rand() * 2);
			my $flag_r = int(rand() * 2);
			my $packed = pack("B*", "011111" . "$regs_b" . "$flag_o" . "100001010" . "$flag_r");
			my $failed = 0;
			
			foreach (unpack("C*", $packed)) {
				$failed++ if index($badChars, chr($_)) != -1;
			}
			next if $failed;
			
			return ($packed x  ($length / 4));
		}
	}

	return(pack('N',0x60606060) x ($length / 4));  
}

1;
