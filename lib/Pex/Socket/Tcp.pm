
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

sub new {
  my $class = shift;
  my $self = bless({ }, $class);

  my $hash = { @_ };
  $self->SetOptions($hash);
  return($self->_newSSL(@_)) if($self->SSL);
  $self->Init;

  $self->_MakeSocket;
# We always return an object, even on errors
#  return if(!$self->_MakeSocket);
  return($self)
}

sub new_from_socket {
  my $class = shift;
  my $sock = shift;
  my $self = bless({ }, $class);
  my $hash =
  eval 
  {
    {
    	LocalAddr => $sock->sockhost,
    	LocalPort => $sock->sockport,
    	PeerAddr  => $sock->peerhost,
    	PeerPort  => $sock->peerport, 
    }
  };

  # Verify that the socket is actually one
  if ($@) {
  	$self->SetError("Socket argument: $@");
	return $self;
  }

  $self->SetOptions($hash);
  $self->Init;
  
  $self->Socket($sock);
  $sock->blocking(0);
  $sock->autoflush(1);
  return ($self);
}

sub SetOptions {
  my $self = shift;
  my $hash = shift;
  $self->SUPER::SetOptions($hash);

  $self->SSL($hash->{'SSL'}) if(exists($hash->{'SSL'}));
}

sub _newSSL {
  use Pex::Socket::SSLTcp;
  my $self = shift;
  return(Pex::Socket::SSLTcp->new(@_));
}

sub SSL {
  my $self = shift;
  $self->{'SSL'} = shift if(@_);
  return($self->{'SSL'});
}



sub Proxies {
  my $self = shift;
  $self->{'Proxies'} = shift if(@_);
  $self->{'Proxies'} = [ ] if(ref($self->{'Proxies'}) ne 'ARRAY');
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

  my $proxies = $self->Proxies;
  if($localPort && @{$proxies}) {
    $self->SetError('A local port was specified and proxies are enabled, they are mutually exclusive.');
    return;
  }

  my $sock;
  if(@{$proxies}) {
    $sock = $self->ConnectProxies($host, $port);
    return if(!$sock);
  } 
  else {
    my %config = (
      'PeerAddr'  => $host,
      'PeerPort'  => $port,
      'Proto'     => 'tcp',
      'ReuseAddr' => 1,
      'Timeout'   => $self->Timeout,
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

sub _MakeSocket {
  my $self = shift;

  return if($self->GetError);

  my $sock = $self->TcpConnectSocket($self->PeerAddr, $self->PeerPort, $self->LocalPort);
  return if($self->IsError || !$sock);

  $self->Socket($sock);

  $sock->blocking(0);
  $sock->autoflush(1);

  return($sock);
}

# hd did it.
sub ConnectProxies {
    my $self = shift;
    my ($host, $port) = @_;
    my @proxies = @{$self->Proxies};
    my ($base, $sock);

    $base = shift(@proxies);
    push @proxies, ['final', $host, $port];
    
    $sock = IO::Socket::INET->new (
        'PeerAddr'  => $base->[1],
        'PeerPort'  => $base->[2],
        'Proto'     => 'tcp',
        'ReuseAddr' => 1,
        'Timeout'   => $self->Timeout,
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

			# Look for the HTTP response message from the Proxy server
			my $sel = IO::Select->new($sock);
			my $resp = '';

			if ($sel->can_read(10)) {
				while (my $line = <$sock>)  {
					last if $line eq "\r\n";
					$resp .= $line;
				}
			} else {
				$self->SetError("HTTP proxy at $lastproxy->[1]:$lastproxy->[2] failed to respond");
				$sock->close;
				return;
			}

			if ($resp !~ /HTTP\/1\.\d\s+2/) {
				$self->SetError("HTTP proxy at $lastproxy->[1]:$lastproxy->[2] returned an error response");
				print $resp;
				$sock->close;
				return;
			}
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

sub _UnitTest {
  my $class = shift;
  print STDOUT "Connecting to google.com:80 $class\n";
  my $sock = $class->new('PeerAddr' => 'google.com', 'PeerPort', 80);
  if(!$sock || $sock->IsError) {
    print STDOUT "Error creating socket: $!\n";
    return;
  }
  print STDOUT "Calling Google Unit Test\n";
  $class->_UnitTestGoogle($sock);
}

sub _UnitTestGoogle {
  my $class = shift;
  my $sock = shift;

  $sock->TimeoutErrors(1);
  $sock->RecvTimeout(4);

  print STDOUT "Trying a Recv timeout.\n";

  my $data = $sock->Recv(-1, 2);
  if(!length($data) || $sock->IsError) {
    print STDOUT "Error in Recv: " . $sock->GetError . "\n";
  }
 
  $sock->ClearError;

  $sock->Send("GET / HTTP/1.1\r\nConnect: keep-alive\r\n\r\n");

  if($sock->IsError) {
    print STDOUT "Error in Send: " . $sock->GetError . "\n";
    return;
  }

  $data = $sock->Recv(-1, 5);
  if(!length($data) || $sock->IsError) {
    print STDOUT "Error in Recv: " . $sock->GetError . "\n";
    return;
  }

  if($data =~ /Server: ([^\s]+)/) {
    print STDOUT "Got server header: $1\n";
  }
  else {
    print STDOUT "Did not find server header\n";
    return;
  }

  print STDOUT "Trying a Recv timeout.\n";

  $data = $sock->Recv(-1, 2);
  if(!length($data) || $sock->IsError) {
    print STDOUT "Error in Recv: " . $sock->GetError . "\n";
  }

  $sock->ClearError;

  print STDOUT "Trying a default Recv timeout.\n";

  $data = $sock->Recv(-1);
  if(!length($data) || $sock->IsError) {
    print STDOUT "Error in Recv: " . $sock->GetError . "\n";
  }

  print STDOUT "-$data-\n";

  print STDOUT "Test seemed successful\n";

}

1;
