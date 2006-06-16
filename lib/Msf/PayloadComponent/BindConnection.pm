

package Msf::PayloadComponent::BindConnection;
use strict;
use base 'Msf::PayloadComponent::ConnectionHandler';
use IO::Socket::INET;

my $info = {
  'UserOpts' =>
    {
      'LPORT' => [1, 'PORT', 'Listening port for bind shell', 4444],
    },
  'Keys' => ['bind'],
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);
  $self->_Info($self->MergeHashRec($info, $self->_Info));
  return($self);
}

sub SetupHandler {
  my $self = shift;
  $self->PrintLine('[*] Starting Bind Handler.');
}

sub CheckHandler {
  my $self = shift;
  my $host = $self->GetVar('RHOST');
  my $port = $self->GetVar('LPORT');

  my $sock = IO::Socket::INET->new(
    'PeerHost'  => $host,
    'PeerPort'  => $port,
    'Proto'     => 'tcp',
    'Timeout'   => 10,
  );
  
  $self->PrintDebugLine(5, 'Bind loop hit.');
  
  if($sock && $sock->connected) {
    $sock->autoflush(1);
#    $self->PrintLine('$sock->connected returned true. ' . $sock->peerhost . $sock->peerport);
    $self->PipeRemoteIn($sock);
    $self->PipeRemoteOut($sock);
    return(1);
  }

  return(0);
}

sub ShutdownHandler {
  my $self = shift;
  $self->PrintLine('[*] Exiting Bind Handler.');
}

1;
