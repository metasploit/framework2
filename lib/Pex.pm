#!/usr/bin/perl
###############

##
#         Name: Pex.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex;

use Pex::Socket;
use Pex::Utils;

use Pex::MSSQL;

use POSIX;
use IO::Socket;
use IO::Select;


sub LoadExploits
{
    my $dir = shift;
    my $res = {};
    
    return $res if ! -d $dir;
    return $res if ! opendir(EXP, $dir);
    
    while (defined(my $entry = readdir(EXP)))
    {
        my $path = "$dir/$entry";
        next if ! -f $path;
        next if $entry !~ /.pm$/;
        
        $entry =~ s/\.pm$//g;

        # remove the module from global namespace
        delete($::{$entry."::"});

        # load the module via do since we dont import
        eval("do '$path'");
        
        if ($@) { print STDERR "[*] Error loading $path: $@\n" }
        else  { $res->{$entry} = $entry->new() }
    }
    closedir(EXP);
    return($res);
}

sub LoadPayloads
{
    my $dir = shift;
    my $res = {};
    
    return $res if ! -d $dir;
    
    # Load internal payloads first
    if (opendir(PAY, "$dir/int"))
    {
        while (defined(my $entry = readdir(PAY)))
        {
            my $path = "$dir/int/$entry";
            next if ! -f $path;

            my $pay = Pex::Payload->new($path, "i");
            $res->{$pay->Name()} = $pay if $pay;
        }
        closedir(PAY);
    }
    
    # Now load all external payloads
    if (opendir(PAY, "$dir/ext"))
    {
        while (defined(my $entry = readdir(PAY)))
        {
            my $path = "$dir/ext/$entry";
            if (! $^O eq "MSWin32")
            {
                next if ! -x $path;
            } else {
                next if ! -f $path;
            }
            
            my $pay = Pex::Payload->new($path, "e");
            $res->{$pay->Name()} = $pay if $pay;
        }
        closedir(PAY);
    }    
    
    return($res);
}

sub PatternCreate
{
    my ($length) = @_;
    my ($X, $Y, $Z);
    my $res;

    while (1)
    {
        for my $X ("A" .. "Z") { for my $Y ("a" .. "z") { for my $Z (0 .. 9) {
           $res .= $X;
           return $res if length($res) >= $length;

           $res .= $Y;
           return $res if length($res) >= $length;

           $res .= $Z;
           return $res if length($res) >= $length;
        }}}
    }
}

sub PatternOffset
{
       my ($pattern, $address) = @_;
       my @results;
       my ($idx, $lst) = (0,0);

       $address = pack("L", eval($address));
       $idx = index($pattern, $address, $lst);

       while ($idx > 0)
       {
            push @results, $idx;
            $lst = $idx + 1;
            $idx = index($pattern, $address, $lst);
       }
       return @results;
}

sub Unblock {
    my $fd = shift || return;
    
    # Using the "can" method $fd->can() does not work
    # when dealing with subclasses of IO::Handle :(
    if (ref($fd) =~ /Socket|GLOB/)
    {
        $fd->blocking  (0);
        $fd->autoflush (1);
    }
    
    if ($^O ne "MSWin32")
    {
        my $flags = fcntl($fd, F_GETFL,0);
        fcntl($fd, F_SETFL, $flags|O_NONBLOCK);
    }
}


# Create a UDP socket to a random internet host and use it to 
# determine our local IP address, without actually sending data
sub InternetIP {
    my $res = "127.0.0.1";
    my $s = IO::Socket::INET->new(PeerAddr => '4.3.2.1', PeerPort => 53, Proto => "udp") 
    || return $res;    
    $res = $s->sockhost;   
    $s->close();
    undef($s);
    return $res;
}


1;
