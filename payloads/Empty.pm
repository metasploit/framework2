package Msf::Payload::Empty;
use strict;
use base 'Msf::Payload';

my $info =
{
    Name         => 'Empty',
    Version      => '1.0',
    Description  => 'Empty payload (for testing)',
    Author       => 'spooney mc spoon spoon',
    Priv         => 0,
    Multistage   => 0,
    Type         => '',
    Size         => '0',
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
