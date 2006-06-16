

package Msf::PayloadComponent::NoConnection;
use strict;
use base 'Msf::PayloadComponent::ConnectionHandler';

my $info = {
  'Keys' => ['noconn'],
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);
  $self->_Info($self->MergeHashRec($info, $self->_Info));
  return($self);
}


1;
