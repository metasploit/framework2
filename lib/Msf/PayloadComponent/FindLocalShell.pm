

package Msf::PayloadComponent::FindLocalShell;
use strict;
use base 'Msf::PayloadComponent::ConnectionHandler';
use IO::Socket::INET;
use IO::Select;

my $info = {
  'Keys' => ['findlocalshell'],
  'UserOpts' => { },
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);
  $self->_Info($self->MergeHashRec($info, $self->_Info));
  return($self);
}


# This can handle a socketpair or other IO::Handle construt
sub ChildHandler {
  my $self = shift;
  my $sock = shift;
  my $data;

  return if ! $sock;  
  
  my $save;
  
  eval {
    $sock->autoflush(1);
  
    $save = $sock->blocking;
    $sock->printflush("echo ABCDEFG\n");
    $sock->blocking(0);

    select(undef, undef, undef, 0.50);
  
    $sock->sysread($data, 4096);
    $sock->blocking($save);
  };

  if($data =~ /ABCDEFG/) {
    $self->PipeRemoteIn($sock);
    $self->PipeRemoteOut($sock);
    $self->PrintLine('[*] Found shell...');
    $self->HandleConsole;
    exit(0);
  }

  return;
}

sub SigHandler {
  my $self = shift;
}

1;
