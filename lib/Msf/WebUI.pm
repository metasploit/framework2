#!/usr/bin/perl
###############

##
#         Name: WebUI.pm
#       Author: spoonm <ninjatools [at] hush.com>
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#  Description: Instantiable class derived from TextUI with methods useful to
#               web-based user interfaces.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::WebUI;
use strict;
use base 'Msf::TextUI';
use Msf::ColPrint;
use IO::Socket;
use POSIX;

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);

  # configure STDERR/STDERR for text display
  select(STDERR); $|++;
  select(STDOUT); $|++;
  
  # create a new empty printline buffer
  $self->SetTempEnv('PrintLine', [ ]);
  $self->_OverridePrintLine(\&PrintLine);
  
  return($self);
}

# We overload the UI::PrintLine call so that we can
# buffer exploit output and display as needed
sub PrintLine {
    my $self = shift;
    my $msg = shift;
    
    # If we are exploit mode, write output to browser
    if (my $s = $self->GetEnv('BROWSER'))
    {
        $s->send("$msg\n");
        return;
    }
    
    my @buffer = @{$self->GetEnv('PrintLine')};
    push @buffer, $msg;
    $self->SetTempEnv('PrintLine', \@buffer);
}

sub DumpLines {
    my $self = shift;
    my @res  = @{$self->GetEnv('PrintLine')};
    $self->SetTempEnv('PrintLine', [ ]);
    return \@res;
}

1;
