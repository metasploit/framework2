package Msf::EncodedPayload;
use strict;
use base 'Msf::Base';

sub new {
  my $class = shift;
  my $self = $class->SUPER::new;
  $self->{'RawPayload'} = shift;
  $self->{'EncodedPayload'} = shift;
  $self->{'Nops'} = shift;
  return($self);
}

sub RawPayload {
  my $self = shift;
  return($self->{'RawPayload'} = shift) if(@_);
  return($self->{'RawPayload'});
}
sub EncodedPayload {
  my $self = shift;
  return($self->{'EncodedPayload'} = shift) if(@_);
  return($self->{'EncodedPayload'});
}
sub Nops {
  my $self = shift;
  return($self->{'Nops'} = shift) if(@_);
  return($self->{'Nops'});
}
sub NopsLength {
  my $self = shift;
  return(length($self->Nops));
}
sub Payload {
  my $self = shift;
  return($self->Nops . $self->EncodedPayload);
}

1;
