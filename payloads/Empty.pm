package Msf::Payload::Empty;
use strict;
use base 'Msf::PayloadComponent::NoConnection';

my $info =
{
    'Name'         => 'Empty',
    'Version'      => '$Revision$',
    'Description'  => 'Empty payload (for testing)',
    'Authors'      => [ 'spoonm <ninjatools [at] hush.com>', ],
    'Priv'         => 0,
};

sub new {
    my $class = shift;
    my $self = $class->SUPER::new({'Info' => $info}, @_);
    return($self);
}

# bypass the size > 0 check
sub Loadable {
  my $self = shift;
  return($self->DebugLevel > 0);
}

sub Build {
  my $self = shift;
  return('');
}

1;
