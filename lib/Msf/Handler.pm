#!/usr/bin/perl
###############

##
#         Name: Handler.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::Handler;
use base 'Msf::Module';
use IO::Socket;
use IO::Select;
use strict;

sub new { return bless {}, shift }

sub Error { my $self = shift; return $self->{ERROR} }
sub set_error { my ($self, $msg) = @_; $self->{ERROR} = $msg }

sub DataPump
{
    my ($self, $cli, $svr, $callback) = @_;
    my $interrupt = 0;

    if (ref($callback) ne "CODE") { $callback = sub { }; }

    $SIG{"PIPE"} = 'IGNORE';
    $SIG{"INT"}  = sub { $interrupt++ };

    my $con;
    my $sel = IO::Select->new();

    $sel->add($cli);
    $sel->add($svr);

    while (fileno($svr) && $interrupt == 0)
    {
        my $fd;
        my @fds = $sel->can_read(0.5);
        foreach $fd (@fds)
        {
	    my $rdata;
            my $bytes = sysread($fd, $rdata, 2048);

            if(! defined($bytes) || $bytes == 0)
            {
                close($svr);
    		$interrupt++;
                $callback->("CLOSED");
            } else {
                # pass data between socket and console
                my $dataq = $rdata;
                if ($fd eq $svr)
                {
                    $callback->("DATA", "SERVER", $rdata);
                    while (length($dataq) && (my $x = syswrite($cli, $dataq, 2048)))
                    {
                        # print STDERR "[*] Wrote to client $x of " . length($dataq) . "\n";
                        $dataq = substr($dataq, $x);
                    }
                } else {
                    $callback->("DATA", "CLIENT", $rdata);
                    while (length($dataq) && (my $x = syswrite($svr, $dataq, 2048)))
                    {
                        # print STDERR "[*] Wrote to server $x of " . length($dataq) . "\n";
                        $dataq = substr($dataq, $x);
                    }
                }
            }
        }
    }

    $callback->("FINISHED");
    return(1);
}


sub DataPumpXor
{
    my ($self, $cli, $svr, $callback, $key) = @_;
    my $interrupt = 0;

    if (ref($callback) ne "CODE") { $callback = sub { }; }

    $SIG{"PIPE"} = 'IGNORE';
    $SIG{"INT"}  = sub { $interrupt++ };

    my $con;
    my $sel = IO::Select->new();

    $sel->add($cli);
    $sel->add($svr);

    while (fileno($svr) && $interrupt == 0)
    {
        my $fd;
        my @fds = $sel->can_read(0.5);
        foreach $fd (@fds)
        {
	        my $rdata;
            my $bytes = sysread($fd, $rdata, 2048);

            if(! defined($bytes) || $bytes == 0)
            {
                close($svr);
    		    $interrupt++;
                $callback->("CLOSED");
            } else {
                # pass data between socket and console
                my $dataq = $rdata;
                my $dxorq;
                
                foreach my $c (split(//, $dataq))
                {
                    $dxorq .= chr(ord($c) ^ $key);
                }
                
                if ($fd eq $svr)
                {
                    $callback->("DATA", "SERVER", $dxorq);
                    while (length($dataq) && (my $x = syswrite($cli, $dxorq, 2048)))
                    {
                        # print STDERR "[*] Wrote to client $x of " . length($dataq) . "\n";
                        $dataq = substr($dataq, $x);
                    }
                } else {
                    $callback->("DATA", "CLIENT", $dxorq);
                    while (length($dataq) && (my $x = syswrite($svr, $dxorq, 2048)))
                    {
                        # print STDERR "[*] Wrote to server $x of " . length($dataq) . "\n";
                        $dataq = substr($dataq, $x);
                    }
                }
            }
        }
    }

    $callback->("FINISHED");
    return(1);
}


# This routine handles a situation where the read and write handles are 
# different for the socket, but the same for the console
sub DataPumpSplit
{
    my ($self, $cli, $svr_to, $svr_from,  $callback) = @_;
    my $interrupt = 0;

    if (ref($callback) ne "CODE") { $callback = sub { }; }

    $SIG{"PIPE"} = 'IGNORE';
    $SIG{"INT"}  = sub { $interrupt++ };

    my $con;
    my $sel = IO::Select->new();

    $sel->add($cli);
    $sel->add($svr_from);

    while (fileno($svr_from) && $interrupt == 0)
    {
        my $fd;
        my @fds = $sel->can_read(0.5);
        foreach $fd (@fds)
        {
	        my $rdata;
            my $bytes = sysread($fd, $rdata, 2048);

            if(! defined($bytes) || $bytes == 0)
            {
                close($svr_from);
                close($svr_to);
    		    $interrupt++;
                $callback->("CLOSED");
            } else {
                # pass data between socket and console
                my $dataq = $rdata;
                if ($fd eq $svr_from)
                {
                    $callback->("DATA", "SERVER", $rdata);
                    while (length($dataq) && (my $x = syswrite($cli, $dataq, 2048)))
                    {
                        #print STDERR "[*] Wrote to client $x of " . length($dataq) . "\n";
                        $dataq = substr($dataq, $x);
                    }
                } else {
                    $callback->("DATA", "CLIENT", $rdata);
                    while (length($dataq) && (my $x = syswrite($svr_to, $dataq, 2048)))
                    {
                        #print STDERR "[*] Wrote to server $x of " . length($dataq) . "\n";
                        $dataq = substr($dataq, $x);
                    }
                }
            }
        }
    }

    $callback->("FINISHED");
    return(1);
}

1;
