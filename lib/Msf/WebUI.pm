#!/usr/bin/perl
###############

##
#         Name: WebUI.pm
#       Author: spoonm <ninjatools [at] hush.com>
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#  Description: Instantiable class derived from TextUI with methods useful to
#                      web-based user interfaces.
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

  # configure STDOUT/STDERR for text display
  select(STDERR); $|++;
  select(STDOUT); $|++;
  
  # create a new empty printline buffer
  $self->SetTempEnv('_PrintLineBuffer', [ ]);
  $self->_OverridePrintLine(\&PrintLine);
  
  return($self);
}

# We overload the UI::PrintLine call so that we can
# buffer the output from the exploit and display it
# as needed
sub PrintLine {
    my $self = shift;
    my $msg = shift;

    # ignore empty messages
    return(0) if ! length($msg);
	
	# XXX XSS checks go here
	
    # If we are in exploit mode, write output to browser
    if (my $s = $self->GetTempEnv('_BrowserSocket')) {
		$msg .= "\n";
		$s->Send(sprintf("%x\n%s", length($msg), $msg));
        return;
    }
    
    my @buffer = @{$self->GetEnv('_PrintLineBuffer')};
    push @buffer, $msg;
    $self->SetTempEnv('_PrintLineBuffer', \@buffer);
    return(1);
}

sub PrintError {
	my $self = shift;
    my $msg  = shift;
    return(0) if ! length($msg);
    return(0) if ! $self->IsError;
    $self->PrintLine("Error: $msg");
    $self->ClearError;
    return(1);
}


sub DumpLines {
    my $self = shift;
    my @res  = @{$self->GetEnv('_PrintLineBuffer')};
    $self->SetTempEnv('_PrintLineBuffer', [ ]);
    return \@res;
}

1;
