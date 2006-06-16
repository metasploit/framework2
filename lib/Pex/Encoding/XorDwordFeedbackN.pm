
###############

##
#         Name: XorDwordFeedback.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::Encoding::XorDwordFeedbackN;
use strict;
use base 'Pex::Encoding::XorDwordFeedback';
use Pex::Encoder;
use Pex::Text;
use Pex::Utils;

sub _PackType {
  my $self = shift;
  return('N');
}

1;
