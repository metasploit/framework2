package Pex::Poly::RegAssassin;
use strict;
use Pex::Utils;

sub new {
  my $class = shift;
  my $self = bless({ }, $class);
  $self->AddData(@_) if(@_);
  return($self);
}
sub _Data {
  my $self = shift;
  $self->{'_Data'} = shift if(@_);
  return($self->{'_Data'});
}
sub _Sets {
  my $self = shift;
  $self->{'_Sets'} = shift if(@_);
  $self->{'_Sets'} = [ ] if(ref($self->{'_Sets'}) ne 'ARRAY');
  return($self->{'_Sets'});
}
sub AddData {
  my $self = shift;
  foreach my $data (@_) {
    $self->_Data($self->_Data . $data);
  }
}
sub AddSet {
  my $self = shift;
  my $names = shift;
  my $vals = shift;
  push(@{$self->_Sets}, [ $names, $vals ]);
}

sub Build {
  my $self = shift;
  my $data = $self->_Data;

  foreach my $set (@{$self->_Sets}) {
    my $names = $set->[0];
    my @vals = @{$set->[1]};
    Pex::Utils::FisherYates(\@vals);
    foreach my $name (@{$names}) {
#      print STDERR "- @vals -\n";
      my $val = pop(@vals);
#      print STDERR "$name -> $val\n";
      $data =~ s/\|\|$name\|\|/$val/g;
    }
  }
  return($data);
}

1;
