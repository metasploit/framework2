
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Nop::SPARC;
use strict;
use base 'Msf::Nop';
use Pex::Utils;

my $info = {
  'Name'    => 'SPARC Nop Generator',
  'Version' => '$Revision$',
  'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],
  'Arch'    => [ 'sparc' ],
  'Desc'    =>  'Sparc nop generator based on ADMutate nop sleds',
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
    my $random  = $self->GetLocal('RandomNops');
    my $badChars = $exploit->PayloadBadChars;
    my @sparc;
    
    # ripped from ADMutate, will add real nop engine later
    push @sparc, "\xa2\x1c\x80\x12";       # /*xor %l2,%l2,%l1   */
    push @sparc, "\xb6\x06\x40\x1a";       # /*add %i1,%i2,%i3   */
    push @sparc, "\xa0\x26\xe0\x42";       # /*sub %i3,0x42,%l0  */
    push @sparc, "\xb6\x16\x40\x1a";       # /*or  %i1,%i2,%i3   */
    push @sparc, "\xb2\x03\x60\x42";       # /*add %o5,0x42,%i1  */
    push @sparc, "\xb6\x04\x80\x12";       # /*add %l2,%l2,%i3   */
    push @sparc, "\xa4\x04\xe0\x42";       # /*add %l3,0x42,%l2  */
    push @sparc, "\x96\x23\x60\x42";       # /*sub %o5,0x42,%o3  */
    push @sparc, "\x96\x24\x80\x12";       # /*sub %l2,%l2,%o3   */
    push @sparc, "\xb2\x26\x80\x19";       # /*sub %i2,%i1,%i1   */
    push @sparc, "\x89\xa5\x08\x22";       # /*fadds %f20,%f2,%f4*/
    push @sparc, "\xa2\x1a\x40\x0a";       # /*xor %o1,%o2,%l1   */ 
    push @sparc, "\xa4\x32\xa0\x42";       # /*orn %o2,0x42,%l2  */
    push @sparc, "\xa2\x03\x40\x12";       # /*add %o5,%l2,%l1   */
    push @sparc, "\xba\x56\xa0\x42";       # /*umul %i2,0x42,%i5 */
    push @sparc, "\xa4\x27\x40\x12";       # /*sub %i5,%l2,%l2   */
    push @sparc, "\xa2\x0e\x80\x13";       # /*and %i2,%l3,%l1   */
    push @sparc, "\xb6\x03\x60\x42";       # /*add %o5,0x42,%i3  */
    push @sparc, "\x98\x3e\x80\x12";       # /*xnor %i2,%l2,%o4  */

    
    if (! $random) {
        return(pack('N',$sparc[0]) x ($length / 4));
    }
    
    # no randomness yet :/
    return(pack('N',$sparc[0]) x ($length / 4));
}


1;
