#!/usr/bin/perl
###############

##
#         Name: HandlerWeb.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#  Description: Payload Handlers for web server UI
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::HandlerWeb;
use base 'Msf::HandlerCLI';
use IO::Socket;
use IO::Select;
use POSIX;
use Pex;

use strict;


sub shell_proxy
{
    my ($self, $shell) = @_;
    my $b = $self->GetVar('BROWSER');
    
    my $s = IO::Socket::INET->new (
                Proto => "tcp",
                LocalPort => 0,
                Type => SOCK_STREAM,
                ReuseAddr => 1,
                Listen => 5
    );

    # the findsock handler passes a non-socket as the shell
    if ($shell->can("sockhost"))
    {
        $b->send("[*] Processing connection: " . 
                 $shell->sockhost . ":" . $shell->sockport . " -- " .
                 $shell->peerhost . ":" . $shell->peerport . "\n");
    }
    
    $b->send("[*] Proxy shell started on port ". $s->sockport ."\n");
    $b->send("[*] Please click <a href='telnet://" . Pex::InternetIP() .":".$s->sockport."'>here</a>.<br>\n");

    my $proxy = fork(); 
    return ($proxy, $s) if $proxy;
    

    $SIG{"TERM"} = sub { exit(0) };
    $SIG{"INT"}  = sub { exit(0) };
    
    my $birth = time();
    Pex::Unblock($s);
    
    my $sel = IO::Select->new($s);

    while ($birth + 300 > time())
    {
        my @X = $sel->can_read(0.5);
        if (scalar(@X))
        {
            # XXX - no access control!!!
            my $victim = $s->accept();

            $victim->send("[*] Welcome to the Shell Proxy :)\n");
            
            if ($shell->can("sockhost"))
            {
                $victim->send("[*] Connected to " . $shell->peerhost . ":" . $shell->peerport . "\n\n");
            }
            
            $self->DataPump($shell, $victim, sub { });
            
            $victim->send("[*] Exiting Shell Proxy...\n");
            $victim->close();
            undef($victim);
            exit(0);
        }
    }
}

1;
