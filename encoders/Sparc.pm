
#
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::Sparc;
use strict;
# use the base from the lib/Msf/Encoder dir
# makes for easier standalone use...
use base 'Msf::Encoder::_Sparc';
use Pex::SPARC;

my $advanced = 
{

};

my $info = {
    'Name'    => 'Sparc DWord Xor Encoder',
    'Version' => '$Revision$',
    'Authors' => [ 'optyx <optyx [at] uberhax0r.net>' ],
    'Arch'    => [ 'sparc' ],
    'OS'      => [ ],
    'Description'  =>  "optyx's 48 byte XOR decoder",
    'Refs'    => [ ],
};

sub new {
    my $class = shift; 
    return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

# I'm a fun msf module stub, mostly just for info data, see
# lib/Msf/Encoder/_Sparc.pm for the real dealz yall


1;
