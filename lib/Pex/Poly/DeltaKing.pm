package Pex::Poly::DeltaKing;
use strict;
use Pex::Text;

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
sub AddData {
  my $self = shift;
  foreach my $data (@_) {
    $self->_Data($self->_Data . $data);
  }
}

sub Build {
  my $self = shift;
  my $data = $self->_Data;

  my @tags;
  my %labels;

  my $diff = 0;
  while($data =~ /(\[>(\d+) .*?<\])/g) {
    my $tag = $1;
    my $size  = $2;
    $diff += length($tag);
    my $pos = pos($data) - $diff;
    $diff -= $size;
#    print "-- $size - $tag - $pos\n";
    push(@tags, [$tag, $pos, $size]);
  }
  # Go throw, removing the [> <] tags (leaving behind space
  # holders and saving labels.
  foreach my $t (@tags) {
    my $tag = $t->[0];
    my $pos = $t->[1];
    my $size = $t->[2];

    my $foo = substr($data, $pos, length($tag), ' ' x $size);
    # label
    if($t->[2] == 0) {
      $tag =~ /\[>(\d+) (.*?)<\]/;
      my $size = $1;
      my $tdata = $2;
#      print "++ $foo ++ $tdata\n";
      $labels{$tdata} = $pos;
    }
  }

  # copy/paste, arg
  foreach my $t (@tags) {
    next if($t->[2] == 0);
    my $tag = $t->[0];
    my $pos = $t->[1];
    $tag =~ /\[>(\d+) (.*?)<\]/;
    my $size = $1;
    my $tdata = $2;

    $tdata =~ s/:(\w+):/\$labels{\'$1\'}/gi;
#    print "!! $tdata\n";
    my $rep = substr(eval($tdata), 0, $size);
#    print "- $@\n";
    my $foo = substr($data, $pos, $size, $rep); # just to make sure
#    print "++ $foo ++\n" . Pex::Text::BufferC($rep);
  }

  return($data);
}

1;
