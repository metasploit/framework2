#!/usr/bin/perl
###############

##
#         Name: msfpayload.cgi
#       Author: H D Moore <hdm [at] metasploit.com>
#      Purpose: Web interface for generating payloads
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

require 5.6.0;

use strict;

use POSIX;

use lib "/home/httpd/code/framework/lib";
use Msf::TextUI;
use Pex;
use CGI qw/:standard/;

my $query = new CGI;
print $query->header(),
 
my $ui = Msf::TextUI->new("/home/httpd/code/framework");

my $payloadsIndex = $ui->LoadPayloads;
my $payloads = { };
my $opt = { };

foreach my $key (keys(%{$payloadsIndex})) {
    $payloads->{$payloadsIndex->{$key}->Name} = $payloadsIndex->{$key};
}

my @params = defined($query->param) ? $query->param : ( );

foreach my $name (@params) { $opt->{uc($name)} = $query->param($name) }

my $action = uc($opt->{'ACTION'});

if (! exists($opt->{'PAYLOAD'}) || ! exists($payloads->{$opt->{'PAYLOAD'}}))
{
    DisplayHeader("Available Payloads");
    DisplayPayloads();
    DisplayFooter();

}


my $sel = $opt->{'PAYLOAD'};
my $p = $payloads->{$sel};
my $popts = $p->UserOpts;

if (! $action)
{   
    DisplayHeader("Payload Information");
    print $query->start_form;
    
    print "<input type='hidden' name='PAYLOAD' value='$sel'>\n";
    print "<input type='hidden' name='ACTION'  value='BUILD'>\n";
    
    print "<table width=800 cellspacing=0 cellpadding=4 border=0>\n";
    PrintRow("Name",            $sel);
    PrintRow("Version",         $p->Version);
    PrintRow("Author",          $p->Author);
    PrintRow("Architecture",    join(" ", @{$p->Arch}));
    PrintRow("Privileged",      ($p->Priv ? "Yes" : "No"));
    PrintRow("Supported OS",    join(" ", @{$p->OS()}));
    PrintRow("Handler Type",    $p->Type);
    PrintRow("Total Size",      $p->Size);

    if (scalar(keys(%{$p->UserOpts})))
    {
        my $subtable = "<table cellspacing=0 cellpadding=4 border=0>\n";
        foreach my $popt (sort(keys(%{$popts})))
        {

            my $dflt = $popts->{$popt}->[3];
            my $reqd = $popts->{$popt}->[0] ? "Required" : "Optional";

            $subtable .= "<tr><td><b>$popt</b></td>".
                         "<td>$reqd</td><td>". $popts->{$popt}->[1] ."</td>".
                         "<td><input type='text' name='$popt' value='$dflt'></td>".
                         "<td>".$popts->{$popt}->[2]."</td></tr>\n"; 
        }
        $subtable .= "</table>\n";
        PrintRow("Payload Options", $subtable);
    }
    print "</table><br><br>\n";
    
    print "<table width=800 cellspacing=0 cellpadding=4 border=0>\n";
    PrintRow("Encode Payload", "<input type='checkbox' name='ENCODE' CHECKED'>");
    PrintRow("Bad Characters", "<input type='text' name='BADCHARS' value='0x00'>");
    print "</table><br>\n";
    print "<center><input type='submit' value='Generate Shellcode'><br></center>\n";
    print $query->end_form;
        
    DisplayFooter();
    exit(0);
}

if ($action eq "BUILD")
{
    DisplayHeader("Generating Payload");

    my $optstr;
    foreach (keys(%{$popts})) 
    {
        if(defined($opt->{$_}))
        {
            $optstr.= "$_=".$opt->{$_}
        }
    }


    my $s = $p->Build($opt);
    if (! $s)
    {
        print "<b>Error</b>: Shellcode build error: " . $p->Error() . "<br>\n";
        DisplayFooter();
        exit(0);
    }

    my $ctitle = "Raw Shellcode";
    
    if (defined($opt->{'BADCHARS'}) && defined($opt->{'ENCODE'}))
    {
        $ctitle = "Encoded Shellcode [";
        my $badchars;
        foreach my $hc (split(/\s+/, $opt->{'BADCHARS'}))
        {
            if ($hc =~ m/^0x(.|..)/) 
            {
                $badchars .= chr(hex($hc));
                $ctitle .= sprintf("\\x%.2x", hex($hc));
            }
        }
        $ctitle .= "]";
        
        my $e = Pex::Encoder::Encode($s, $badchars);
        if (! $e)
        {
            print "<b>Error</b>: The encoder was not able to encode this payload<br>\n";
            DisplayFooter();
            exit(0);
        }
        $s = $e;
    }

    my ($sC, $sP) = (Pex::Utils::BufferC($s), Pex::Utils::BufferPerl($s));
    print "<pre>\n";
    
    print "/* $ctitle ($sel) [$optstr] http://metasploit.com /*\n";
    print "unsigned char scode[] =\n$sC\n\n\n";
    
    print "# $ctitle ($sel) [$optstr] http://metasploit.com\n";
    print "my \$shellcode =\n$sP\n\n\n";




    DisplayFooter();
    exit(0);
}


DisplayHeader("Unknown Action");
print "Invalid action specified.";
DisplayFooter();
exit(0);


sub DisplayHeader {
    my $title = shift;
    print $query->start_html($title),
}

sub DisplayFooter {
    print $query->end_html();
}

sub DisplayPayloads {
    print $query->start_form;
    print "Select a payload";
    foreach my $p (keys(%{$payloads}))
    {
        print "<input type='radio' name='PAYLOAD' value='$p'>".$payloads->{$p}->Name."<br>\n";
    }
    print "<input type='submit' value='Select Payload'><br>\n";
    print $query->end_form;
}

sub PrintRow {
    print "<tr valign='top'>";
    print "<td align='right'><b>" . shift(@_) . ":</b></td>";
    foreach (@_) { print "<td>$_</td>" }
    print "</tr>\n";
}

sub CreateRow {
    my $res = "<tr align='center'>";
    foreach (@_) { $res .= "<td>$_</td>" }
    $res .= "</tr>\n";
    return($res);
}
__DATA__

my $s = $p->Build($opt);
if (! $s)
{
    print "Error: " . $p->Error() . "\n";
    exit(0);
}

if ($action =~ /^R/) { print $s; exit; }

my $r = $action =~ /^C/ ? Pex::Utils::BufferC($s) : Pex::Utils::BufferPerl($s);

print $r;
exit(0);

sub Usage
{
    print STDERR "   Usage: $0 <payload> [var=val] <S|C|P>\n";
    print STDERR "Payloads: \n";
    foreach my $p (sort(keys(%{$payloads})))
    {
        print STDERR "\t$p" . (" " x (20 - length($p))) . $payloads->{$p}->Description . "\n";
    }
    exit(0);
}
