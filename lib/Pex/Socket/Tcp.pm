#!/usr/bin/perl
###############

##
#         Name: Socket.pm
#       Author: spoonm <ninjatools [at] hush.com>
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::Socket::Tcp;
use strict;
use base 'Pex::Socket::Socket';
use IO::Socket;
use IO::Select;

sub SetOptions {
  my $self = shift;
  my $hash = shift;

  if(exists($hash->{'SSL'})) {
    my $use = $hash->{'SSL'};
    if($SSL_SUPPORT == 0 && $use) {
      $self->SetError('UseSSL option is set, but Net::SSLeay has not been installed.');
      return;
    }
    $self->UseSSL($use);
  }
  
  if(exists($hash->{'Timeout'})) {
    $self->SetTimeout($hash->{'Timeout'});
  }
  
  if(exists($hash->{'SpoofIP'})) {
    $self->SetSpoofIP($hash->{'SpoofIP'});
  }  
  
  return;
}


sub Proxies {
  my $self = shift;
  $self->{'Proxies'} = shift if(@_);
  $self->{'Proxies'} = [ ] if(ref($self->{'Proxies'} ne 'ARRAY');
  return($self->{'Proxies'});
}

sub AddProxy {
  my $self = shift;
  my ($type, $addr, $port) = @_;

  if (! defined($type) || ! defined($addr) || ! defined($port))
  {
    $self->SetError('Invalid proxy value specified');
    return(0);
  }

  if ($type eq 'http')
  {
    push(@{$self->Proxies}, [ $type, $addr, $port ]);
    return(1);
  }
  
  if ($type eq 'socks4')
  {
    push(@{$self->Proxies}, [ $type, $addr, $port ]);
    return(1);
  }
  
  $self->SetError('Invalid proxy type specified');
  return(0);
}

sub TcpConnectSocket {
  my $self = shift;
  my $host = shift;
  my $port = shift;
  my $localPort = shift;

  my $proxies = $self->GetProxies;
  if($localPort && $proxies) {
    $self->SetError('A local port was specified and proxies are enabled, they are mutually exclusive.');
    return;
  }

  my $sock;
  if($proxies) {
    $sock = $self->ConnectProxies($host, $port);
    return if(!$sock);
  } 
  else {
    my %config = (
      'PeerAddr'  => $host,
      'PeerPort'  => $port,
      'Proto'     => 'tcp',
      'ReuseAddr' => 1,
      'Timeout'   => $self->GetConnectTimeout,
    );
    $config{'LocalPort'} = $localPort if($localPort);
    $sock = IO::Socket::INET->new(%config);  
 
    if(!$sock || !$sock->connected) {
      $self->SetError('Connection failed: ' . $!);
      return;
    }
  }

  return($sock);
}

sub Tcp {
  my $self = shift;
  my $host = shift;
  my $port = shift;
  my $localPort = shift;

  return if($self->GetError);

  $self->{'Socket'} = undef;
  $self->SetError(undef);

  my $sock = $self->TcpConnectSocket($host, $port, $localPort);
  return if($self->GetError || !$sock);

  $self->{'Socket'} = $sock;


  if($self->UseSSL) {
    # Create SSL Context
    $self->{'SSLCtx'} = Net::SSLeay::CTX_new();
    # Configure session for maximum interoperability
    Net::SSLeay::CTX_set_options($self->{'SSLCtx'}, &Net::SSLeay::OP_ALL);
    # Create the SSL file descriptor
    $self->{'SSLFd'}  = Net::SSLeay::new($self->{'SSLCtx'});
    # Bind the SSL descriptor to the socket
    Net::SSLeay::set_fd($self->{'SSLFd'}, $sock->fileno);        
    # Negotiate connection
    my $sslConn = Net::SSLeay::connect($self->{'SSLFd'});

    if($sslConn <= 0) {
      $self->SetError('Error setting up ssl: ' . Net::SSLeay::print_errs());
      $self->close;
      return;
    }
  }

  # we have to wait until after the SSL negotiation before 
  # setting the socket to non-blocking mode

  $sock->blocking(0);
  $sock->autoflush(1);

  return($sock->fileno);
}

# hd did it.
sub ConnectProxies {
    my $self = shift;
    my ($host, $port) = @_;
    my @proxies = @{$self->GetProxies};
    my ($base, $sock);

    $base = shift(@proxies);
    push @proxies, ['final', $host, $port];
    
    $sock = IO::Socket::INET->new (
        'PeerAddr'  => $base->[1],
        'PeerPort'  => $base->[2],
        'Proto'     => 'tcp',
        'ReuseAddr' => 1,
        'Timeout'   => $self->GetConnectTimeout,
    );
    if (! $sock || ! $sock->connected)
    {
        $self->SetError("Proxy server type $base->[0] at $base->[1] failed connection: $!");
        return;
    }
    
    my $proxyloop = 0;
    my $lastproxy = $base;
    foreach my $proxy (@proxies)  
    {
        $proxyloop++;
        
        if ($lastproxy->[0] eq 'http') {
            my $res = $sock->send("CONNECT ".$proxy->[1].":".$proxy->[2]." HTTP/1.0\r\n\r\n");
        }
        
        if ($lastproxy->[0] eq 'socks4') {
            $sock->send("\x04\x01".pack('n',$proxy->[2]).gethostbyname($proxy->[1])."\x00");
            $sock->recv(my $res, 8);
            if (! $res || ($res && ord(substr($res,1,1)) != 90)) {
                $self->SetError("Socks4 proxy at $lastproxy->[1]:$lastproxy->[2] failed to connect to ".join(":",@{$proxy}));
                $sock->close;
                return;
            }
        }
        
        # wait 0.25 second for each proxy already in chain
        select(undef, undef, undef, 0.25 * $proxyloop);
        
        if (! $sock->connected) {
            $self->SetError("Proxy type $lastproxy->[0] at $lastproxy->[1] closed connection");
            return;
        }
        
        last if $proxy->[0] eq 'final';
        $lastproxy = $proxy;
    }
    return $sock;
}

1;
