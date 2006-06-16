package Msf::PayloadComponent::CommandPayload;
use strict;
use vars qw{@ISA};

sub _Import {
  my $class = shift;
  @ISA = ();
  foreach (@_) {
    eval("use $_");
    unshift(@ISA, $_);
  }
}

my $info = {
  'Keys' => ['+cmd'],
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
#  $self->_Info->{'Keys'} = [ @{$info->{'Keys'}}, @{$self->Keys} ];
  return($self);
}

sub Build {
  my $self = shift;
  my $commandString = $self->CommandString;
  $self->PrintDebugLine(3, "CMD: $commandString");
  return($commandString);
}

sub CommandString {
  my $self = shift;
  return;
}

sub Size {
  my $self = shift;
  return(length($self->CommandString));
}

sub Loadable {
  return(1);
}

1;
