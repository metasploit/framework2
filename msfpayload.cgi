#!/usr/bin/perl
###############

##
#         Name: msfpayload.cgi
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#  Description: Web interface for generating Metasploit payloads
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

require 5.6.0;
use strict;

use FindBin qw{$RealBin};
use lib "$RealBin/lib";
use Msf::TextUI;
use POSIX;
use Pex;
use CGI qw/:standard/;

Msf::UI::ActiveStateSucks();

my $query = new CGI; 
print $query->header();

my $ui = Msf::TextUI->new($RealBin);
$ui->SetTempEnv('_MsfPayload', 1);

my $opt = { };
my $exploits = { };
my $payloads = { };
my $exploitsIndex = $ui->LoadExploits;
my $payloadsIndex = $ui->LoadPayloads;
my $encoders = $ui->LoadEncoders;
my $nops     = $ui->LoadNops;

foreach my $key (keys(%{$payloadsIndex})) {
    $payloads->{$payloadsIndex->{$key}->Name} = $payloadsIndex->{$key};
}

foreach my $key (keys(%{$exploitsIndex})) {
    $exploits->{$exploitsIndex->{$key}->Name} = $exploitsIndex->{$key};
}

$ui->SetTempEnv('_Exploits', $exploitsIndex);
$ui->SetTempEnv('_Payloads', $payloadsIndex);
$ui->SetTempEnv('_Encoders', $encoders);
$ui->SetTempEnv('_Nops', $nops);

my @params = defined($query->param) ? $query->param : ( );

foreach my $name (@params) 
{
    $ui->SetTempEnv($name, $query->param($name));
    $opt->{$name} = $query->param($name);
}

my $action = uc($opt->{'ACTION'});

if (! exists($opt->{'PAYLOAD'}) || ! exists($payloads->{$opt->{'PAYLOAD'}}))
{
    DisplayHeader("Available Payloads");
    DisplayPayloads();
    DisplayFooter();
    exit(0);
}


my $sel = $opt->{'PAYLOAD'};
my $p = $payloads->{$sel};
my $popts = $p->UserOpts;

if (! $p)
{
    DisplayHeader("Payload Error");
    print "Invalid payload selected.\n";
    DisplayFooter();
    exit(0);
}

$ui->SetTempEnv('_Exploit', $exploits->{'Tester'});
$ui->SetTempEnv('_PayloadName', $sel);
$ui->SetTempEnv('_Payload', $p);

if (! $action)
{   
    DisplayHeader("Payload Information");
    print $query->start_form;
    
    print "<input type='hidden' name='PAYLOAD' value='$sel'>\n";
    print "<input type='hidden' name='ACTION'  value='BUILD'>\n";
    
    print "<table width=800 cellspacing=0 cellpadding=4 border=0>\n";
    PrintRow("Name",            $sel);
    PrintRow("Version",         $p->Version);
    PrintRow("Authors",         join(" ", $p->Authors));
    PrintRow("Architecture",    join(" ", @{$p->Arch}));
    PrintRow("Privileged",      ($p->Priv ? "Yes" : "No"));
    PrintRow("Multistage",      ($p->Multistage ? "Yes" : "No"));
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
    PrintRow("Bad Characters", "<input type='text' name='BadChars' value='0x00'>");
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
        if(defined($opt->{$_}) && length($opt->{$_}))
        {
            $optstr.= " $_=".$opt->{$_};
        }
    }

    my $badchars_bin;
    my $badchars_str;
    if (defined($opt->{'BadChars'}) && defined($opt->{'ENCODE'}))
    {
        foreach my $hc (split(/\s+/, $opt->{'BadChars'}))
        {
            if ($hc =~ m/^0x(.|..)/) 
            {
                $badchars_bin .= chr(hex($hc));
                $badchars_str .= sprintf("\\x%.2x", hex($hc));
            } else {
                # it isn't hex char... maybe just plain char?
                foreach (split(//, $hc))
                {
                    $badchars_bin .= $_;
                    $badchars_str .= sprintf("\\x%.2x", ord($_));  
                }              
            }
        }
        $ui->SetTempEnv('BadChars', $badchars_bin);
    }

    my $s = $ui->Encode;
    if (! $s)
    {
        print "<b>Error</b>: Shellcode build error: " . $ui->Error() . "<br>\n";
        DisplayFooter();
        exit(0);
    }
    my $r = $s->RawPayload;

    my $ctitle = "Raw Shellcode";
    
    if (defined($opt->{'BadChars'}) && defined($opt->{'ENCODE'}))
    {
        $ctitle = "Encoded Shellcode [". $badchars_str ."]";
        $r = $s->EncodedPayload;
    }

    $optstr .= " Size=" . length($r);

    my ($sC, $sP) = (Pex::Utils::BufferC($r), Pex::Utils::BufferPerl($r));
    
    if ($p->Multistage)
    {
        print "<b>Warning:</b> Multistage payloads only return first stage<br><br>\n";
    }
    
    print "<pre>\n";
    
    print "/* $sel - $ctitle [$optstr ] http://metasploit.com */\n";
    print "unsigned char scode[] =\n$sC\n\n\n";
    
    print "# $sel - $ctitle [$optstr ] http://metasploit.com\n";
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
    print $query->start_html(-title => $title, -style=>GetStyle());
}

sub DisplayFooter {
    print $query->end_html();
}

sub DisplayPayloads {

    print "<table width=800 cellspacing=0 cellpadding=4 border=0>\n";
    foreach my $p (sort(keys(%{$payloads})))
    {
        print CreatePayloadRow( $query->start_form . "<input type='hidden' name='PAYLOAD' value='$p'>"."<input type='submit' value='$p'>",
                         $payloads->{$p}->Description . $query->end_form);
    }
    print "</table><br>";
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

sub CreatePayloadRow {
    my $res = "<tr>";
    $res .= "<td align='right'>".shift(@_)."</td>";
    foreach (@_) { $res .= "<td>$_</td>" }
    $res .= "</tr>\n";
    return($res);
}

sub GetStyle {
return qq
[
        <style>
            BODY 
            {
                background:     white;
                font-family:    Verdana, Tahoma, Arial, Helvetica, sans-serif;
                color:          black;
                font-size:      14pt;
                margin:         0;
            }

            A:link          { font-size: 14pt; text-decoration: none; color: navy; font-weight: bold;}
            A:active        { font-size: 14pt; text-decoration: none; color: navy; font-weight: bold;}
            A:visited       { font-size: 14pt; text-decoration: none; color: navy; font-weight: bold;}
            A:hover         { font-size: 14pt; text-decoration: none; color: navy; font-weight: bold;}

        </style>
];
}
