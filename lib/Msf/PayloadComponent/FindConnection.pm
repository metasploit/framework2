

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


# Maximum execution time of this routine is 5 seconds...
sub ChildHandler {
  my $self = shift;
  my $sock = shift;

  my $s = Pex::Socket::Tcp->new_from_socket( $sock );
  print $s->GetError."\n";
  return if $s->IsError;
  
  # Give the payload time to execute
  sleep(1);

  # Flush the recv input buffer
  $s->Recv(-1, 1);

  # Send a test probe
  $s->Send("echo ABCDEFG\r\n");

  # Is three seconds long enough?
  my $resp = $s->Recv(-1, 3);
  
  if($resp =~ /ABCDEFG/) {
    $self->PipeRemoteIn($sock);
    $self->PipeRemoteOut($sock);
    $self->PrintLine('[*] FindConnection found a shell...');
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
