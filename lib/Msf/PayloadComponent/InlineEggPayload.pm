
###############

##
#         Name: InlineEggPayload.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#  Description: Parent class for InlineEgg Payloads.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::PayloadComponent::InlineEggPayload;
use strict;
use base 'Msf::PayloadComponent::ExternalPayload';

# These are sort of duplicates, in order to call Loadable, you need
# a instance, when you call new to get an instance, it calls _GenSize
# in order to Generate a payload so the Loadable can pass the Size > 0
# check.  So we basically prevent loading with the Generate overload, and
# the Loadable is there for good luck.

sub Loadable {
  my $self = shift;
  return($self->GetVar('EnablePython') && $self->SUPER::Loadable);
}

sub Generate {
  my $self = shift;
  return if(!$self->GetVar('EnablePython'));
  return($self->SUPER::Generate(@_));
}

1;
