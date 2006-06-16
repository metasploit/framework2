
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
  $self->_OverridePrint(\&Print); 
  
  return($self);
}

# We overload the UI::PrintLine call so that we can
# buffer the output from the exploit and display it
# as needed

sub Print {
    my $self = shift;
    my $data = shift;
	my $line = shift;

    # ignore empty messages
    return(0) if ! length($data);
	
	# strip out bad web joojoo
	$data = XSS_Filter($data);	
	
	# convert new lines to line breaks
	$data =~ s/\n/\<br\\\>/g;
	
	# append a line break if required
	$data .= "<br/>\n" if $line;

 	# If we are in exploit mode, write output to browser
    if (my $s = $self->GetTempEnv('_BrowserSocket')) {
		
		# automatically scroll to the end of the page...	
		$data .= "<script language='javascript'>self.scrollTo(0, 999999999)</script>\n";		
		$s->Send(sprintf("%x\r\n%s\r\n", length($data), $data));
        return(1);
    }
    
    my @buffer = @{$self->GetEnv('_PrintLineBuffer')};
    push @buffer, $data;
    $self->SetTempEnv('_PrintLineBuffer', \@buffer);	    
	return(1);
}

sub PrintLine {
    my $self = shift;
    my $data = shift;
	return $self->Print($data, 1);	
}

sub PrintError {
	my $self = shift;
    my $data  = shift;
    return(0) if ! length($data);
    return(0) if ! $self->IsError;
    $self->PrintLine("Error: $data");
    $self->ClearError;
    return(1);
}


sub DumpLines {
    my $self = shift;
    my @res  = @{$self->GetEnv('_PrintLineBuffer')};
    $self->SetTempEnv('_PrintLineBuffer', [ ]);
    return \@res;
}

# XXX - not complete
sub XSS_Filter {
	my $data = shift;
	
	$data =~ s/\</\&lt;/g;
	$data =~ s/\>/\&gt;/g;
	return $data;
}

1;
