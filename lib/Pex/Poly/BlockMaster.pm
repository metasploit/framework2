package Pex::Poly::BlockMaster;
use strict;
use Pex::Poly::BlockMaster::Block;

sub new {
  my $class = shift;
  my $self = bless({ }, $class);
  $self->AddBlock(@_) if(@_);
  return($self);
}

sub _Blocks {
  my $self = shift;
  $self->{'_Blocks'} = shift if(@_);
  $self->{'_Blocks'} = [ ] if(ref($self->{'_Blocks'}) ne 'ARRAY');
  return($self->{'_Blocks'});
}
sub _DoneBlocks {
  my $self = shift;
  $self->{'_DoneBlocks'} = shift if(@_);
  $self->{'_DoneBlocks'} = [ ] if(ref($self->{'_DoneBlocks'}) ne 'ARRAY');
  return($self->{'_DoneBlocks'});
}

sub AddBlock {
  my $self = shift;
  push(@{$self->_Blocks}, @_);
}
sub RandBlock {
  my $self = shift;
  return if(!@{$self->_Blocks});
  my $rand = int(rand(@{$self->_Blocks}));
  return($self->_Blocks->[$rand]);
}

sub _ClearDoneBlocks {
  my $self = shift;
  my $array = [ ];
  foreach (@{$self->_Blocks}) {
    push(@{$array}, 0);
  }
  $self->_DoneBlocks($array);
}

sub _BlockDone {
  my $self = shift;
  my $index = $self->_BlockIndex(shift);
  $self->_DoneBlocks->[$index] = shift if(@_);
  return($self->_DoneBlocks->[$index]);
}
sub _BlockIndex {
  my $self = shift;
  my $block = shift;
  my $i = 0;
  foreach my $b(@{$self->_Blocks}) {
    return($i) if($block eq $b);
    $i++;
  }
  return(-1);
}
sub _IsBlockLeft {
  my $self = shift;
  foreach my $done (@{$self->_DoneBlocks}) {
    return(1) if(!$done);
  }
  return(0);
}

sub Build {
  my $self = shift;
  $self->_ClearDoneBlocks;
  my $data;
  while($self->_IsBlockLeft) {
    my $block = $self->RandBlock;
    next if($self->_BlockDone($block));
#    print $block->RandBlock . "\n";
    my $next = $block->NextBlock;
    if(!$next) {
      $self->_BlockDone($block, 1);
      next;
    }
    $data .= $next->Build;
#    print "-- $data\n";
  }
  return($data);
}

1;
