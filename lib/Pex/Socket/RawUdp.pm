
###############

##
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::Socket::RawUdp;
use base "Pex::Socket::Socket";
use strict;

use IO::Socket;
use Pex::RawSocket;
use Pex::RawPackets;

sub new {
  my $class = shift;
  my $self = bless({ }, $class);

  my $hash = { @_ };
  $self->SetOptions($hash);
  $self->Init;
  $self->_MakeSocket;
  return($self)
}

sub SetOptions {
    my $self = shift;
    my $hash = shift;
    $self->Broadcast($hash->{'Broadcast'}) if(exists($hash->{'Broadcast'}));

    my @options = ('PeerAddr', 'PeerPort', 'LocalPort', 'LocalAddr');
        foreach my $option (@options) {
        $self->$option($hash->{$option}) if(exists($hash->{$option}));
    }
}

sub Broadcast {
    my $self = shift;
    $self->{'Broadcast'} = shift if(@_);
    return($self->{'Broadcast'});
}

sub _MakeSocket {
    my $self = shift;
    return if($self->GetError);

    my $sock = Pex::RawSocket->new();
    if (! $sock) {
        $self->SetError('Socket failed: ' . $!);
        return;
    }

    $sock->blocking(0);
    $sock->autoflush(1);
    $self->Socket($sock);
    return($sock);
}

sub Init { 
    my $self = shift;
    if (! $self->LocalAddr) {
        $self->LocalAddr(inet_ntoa(pack('N', rand() * 0xffffffff)));
    }
    if (! $self->LocalPort) {
        $self->LocalPort(rand() * 0xffff);
    }
    if (! $self->PeerAddr) {
        $self->PeerAddr(inet_ntoa(pack('N', rand() * 0xffffffff)));
    }
    if (! $self->PeerPort) {
        $self->PeerPort(rand() * 0xffff);
    }
}

sub Send { 
    my $self = shift;
    my $data = shift;
    return if($self->GetError);
    
    my $x = Pex::RawPackets->new('UDP');
    
    $x->ip_src_ip       ( $self->LocalAddr );
    $x->ip_dest_ip      ( $self->PeerAddr  );
    $x->udp_dest_port   ( $self->PeerPort  );
    $x->udp_src_port    ( $self->LocalPort );
    $x->udp_data        ( $data );
    
    my $r = $self->Socket->send($x->Encode, $self->PeerAddr);
    if ($r != length($data)) {
        $self->SetError('Socket error: send did not return correct value: ' . $!);
        return;
    }

}

# these functions are just stubbed out for raw sockets
sub Recv  { return }
sub Close { return }
sub SocketError { return 0 }

# overload these just in case someone tries to call them
sub Buffer { }
sub AddBuffer { }
sub GetBuffer { }
sub RemoveBuffer { }

# inherit these from Pex::Socket::Socket
# sub Socket { }
# sub PeerAddr { }
# sub PeerPort { }
# sub LocalPort { }
# sub LocalAddr { }
# sub Timeout { }
# sub RecvTimeout { }
# sub RecvLoopTimeout { }
# sub TimeoutErrors { }
# sub SetError { }
# sub GetError { }
# sub IsError { }
# sub ClearError { }

1;
