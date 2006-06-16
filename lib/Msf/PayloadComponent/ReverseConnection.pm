

package Msf::PayloadComponent::ReverseConnection;
use strict;
use base 'Msf::PayloadComponent::ConnectionHandler';
use IO::Socket::INET;
use IO::Select;

my $info = {
  'UserOpts' =>
    {
      'LHOST'         =>  [1, 'ADDR', 'Local address to receive connection'],
      'LPORT'         =>  [1, 'PORT', 'Local port to receive connection', 4321],
    },
  'Keys' => ['reverse'],
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);
  $self->_Info($self->MergeHashRec($info, $self->_Info));
  return($self);
}

sub Protocol
{
  my $self = shift;
  my $proto = $self->_Info->{'Protocol'};

  $proto = 'tcp' if not defined($proto);

  return $proto;
}

sub ListenerSock {
  my $self = shift;
  $self->{'ListenerSock'} = shift if(@_);
  return($self->{'ListenerSock'});
}
sub ListenerSelector {
  my $self = shift;
  $self->{'ListenerSelector'} = shift if(@_);
  return($self->{'ListenerSelector'});
}

sub NinjaSock {
  my $self = shift;
  $self->{'NinjaSock'} = shift if(@_);
  return($self->{'NinjaSock'});
}
sub NinjaSelector {
  my $self = shift;
  $self->{'NinjaSelector'} = shift if(@_);
  return($self->{'NinjaSelector'});
}
sub NinjaWanted {
  my $self = shift;
  return($self->GetVar('NinjaHost') && $self->GetVar('NinjaPort'));
}


sub SetupHandler {
  my $self = shift;
  return($self->NinjaSetupHandler) if($self->NinjaWanted);

  my $port = $self->GetVar('LPORT');
  my $sock;

  if ($self->Protocol eq 'udp')
  {
    $sock = IO::Socket::INET->new(
      'LocalPort' => $port,
      'Proto'     => 'udp');
  }
  else
  {
    $sock = IO::Socket::INET->new(
      'LocalPort' => $port,
      'Proto'     => 'tcp',
      'ReuseAddr' => 1,
      'Listen'    => 5,
      'Blocking'  => 0);
  }

  if(!$sock) {
    $self->SetError("Could not start listener: $!");
    return;
  }

  $sock->autoflush(1);
  $self->ListenerSock($sock);
  $self->ListenerSelector(IO::Select->new($sock));
  $self->PrintLine('[*] Starting Reverse Handler.');
}

sub CheckHandler {
  my $self = shift;
  return($self->NinjaCheckHandler) if($self->NinjaWanted);

  my @ready = $self->ListenerSelector->can_read(.5);
  
  if(@ready) {
    my $sock;
    my $psrc;
	
    if($self->Protocol() eq 'tcp')
    {
      $sock = $ready[0]->accept();
    }
    else
    {
      my ($paddr, $buf, $ip, $port);
      $sock  = $ready[0];
      
      $paddr = recv($sock, $buf, 1024, MSG_PEEK);
      return if ! defined($paddr);
	  
      my ($port, $host_bin) = sockaddr_in($paddr);
      $psrc = $sock->sockhost .":". $sock->sockport ." <-> ". inet_ntoa($host_bin) .":". $port;
    }
    
    $self->PipeRemoteIn($sock);
    $self->PipeRemoteOut($sock);
    $self->PipeRemoteSrc($psrc) if $psrc;

    return(1);
  }

  return(0);
}

sub ShutdownHandler {
  my $self = shift;
  return($self->NinjaShutdownHandler) if($self->NinjaWanted);
  $self->SUPER::ShutdownHandler;
  if($self->ListenerSock) {
    $self->ListenerSock->shutdown(2);
  }
  $self->PrintLine('[*] Exiting Reverse Handler.');
}

sub NinjaSetupHandler {
  my $self = shift;
  my $host = $self->GetVar('NinjaHost');
  my $port = $self->GetVar('NinjaPort');

  my $sock = IO::Socket::INET->new(
    'PeerHost'  => $host,
    'PeerPort'  => $port,
    'Proto'     => 'tcp',
    'Blocking'  => 1,
    'Timeout'   => 10,
  );

  if(!$sock) {
    $self->SetError("Could not start sN connection: $!");
    return;
  }

  $sock->blocking(0);
  $sock->autoflush(1);
  $self->NinjaSock($sock);
  $self->NinjaSelector(IO::Select->new($sock));
  $self->PrintLine('[*] Starting socketNinja Handler.');
}

sub NinjaCheckHandler {
  my $self = shift;
  my $dontKill = $self->GetVar('NinjaDontKill');

  my @ready = $self->NinjaSelector->can_read(.5);
  if(@ready) {
    my $data;
    $self->NinjaSock->recv($data, 4096);
    return if(!length($data));

    while($data =~ /Added server/g) {
      $self->PrintLine('[!] socketNinja has new connection.');
      return(0) if($dontKill);
      return(1);
    }
  }

  return(0);
}

sub HandleConsole {
  my $self = shift;
  return if($self->NinjaWanted);
  $self->SUPER::HandleConsole;
}

sub NinjaShutdownHandler {
  my $self = shift;
  $self->SUPER::ShutdownHandler;
  if($self->NinjaSock) {
    $self->NinjaSock->shutdown(2);
  }
  $self->PrintLine('[*] Exiting socketNinja Handler.');
}

1;
