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
