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


if (! $action)
{
    my $sel = $opt->{'PAYLOAD'};
    my $p = $payloads->{$sel};
    
    DisplayHeader("Payload Information");
    print "\n";
    print "        Name: $sel\n";
    print "     Version: " . $p->Version . "\n";
    print "      Author: " . $p->Author . "\n";
    print "Architecture: " . join(" ", @{$p->Arch}) . "\n";
    print "  Privileged: " . ($p->Priv ? "Yes" : "No") . "\n";
    print "Supported OS: " . join(" ", @{$p->OS()}) . "\n";
    print "Handler Type: " . $p->Type . "\n";
    print "  Total Size: " . $p->Size . "\n\n";
    
    if (scalar(keys(%{$p->UserOpts})))
    {
        foreach my $o (keys(%{$p->UserOpts}))
        {
            print "\t" . $o . (" " x (20 - length($o))) . ($p->UserOpts->{$o}->[0] ? "Y" : "N") .
                  "\t" . $p->UserOpts->{$o}->[1] . "\t" . $p->UserOpts->{$o}->[2] . "\n";
        }
    }
    print "\n";
    DisplayFooter();
    exit(0);
}

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
