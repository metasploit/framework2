package Pex::Poly::BlockMaster;
use strict;
use Pex::Poly::BlockMaster::Block;

sub new {
  my $class = shift;
  my $self = bless({ }, $class);
  $self->AddBlock(@_) if(@_);
  return($self);
}

# These keep the "top" blocks.  It might be a better design decision to force
# a single top block, even if it's empty, but I support more than one for now.
sub _Blocks {
  my $self = shift;
  $self->{'_Blocks'} = shift if(@_);
  $self->{'_Blocks'} = [ ] if(ref($self->{'_Blocks'}) ne 'ARRAY');
  return($self->{'_Blocks'});
}

# Done blocks are an optimization so we don't need to ask each block
# if it's done each time.  Since it's a cascading fall (poor design?), the
# block would have to do a bit of work to decide if it's "done", and since
# once it was done once, it isn't going to be not done later.
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

sub BadChars {
  my $self = shift;
  $self->{'BadChars'} = shift if(@_);
  return($self->{'BadChars'});
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
  foreach my $b (@{$self->_Blocks}) {
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

# We just iterate through the top blocks, calling _BuildInit on each, this will
# get all of the top blocks (and cascade through all connected blocks) ready
# for a new generation (Build call)
sub _BuildInit {
  my $self = shift;
  my $badChars = shift;

  # Prepare myself (BlockMaster) (clear DoneBlocks, etc)
  $self->_ClearState;

  foreach my $b (@{$self->_Blocks}) {
    $b->_BuildInit($badChars);
  }
}

sub _ClearState {
  my $self = shift;
  $self->_ClearDoneBlocks;
}

sub Build {
  my $self = shift;

  # Gets ready y'all
  $self->_BuildInit($self->BadChars);

  my $data;
  while($self->_IsBlockLeft) {
    my $block = $self->RandBlock;
    next if($self->_BlockDone($block));
#    print $block->RandBlock . "\n";
    my $next = $block->_TopNextBlock;
    if(!$next) {
      $self->_BlockDone($block, 1);
      next;
    }
    $data .= $next->Build;
#    print "-- $data\n";
  }
  return($data);
}

# This is a little stubby guy I wrote for generating the graphviz graphs.  It
# will just generate an array of the connections between the blocks.  It
# currently has repeats because of the design of the system and iteration.
sub _Connections {
  my $self = shift;
  my @conns;
  foreach my $b (@{$self->_Blocks}) {
    my @c = $b->_Connections;
    while(@c) {
      my $c1 = shift(@c);
      my $c2 = shift(@c);
      push(@conns, $c1, $c2) if(!$self->_ConnectionExists(\@conns, $c1, $c2));
    }
  }
  return(@conns);
}

sub _ConnectionExists {
  my $self = shift;
  my $array = shift || [ ];
  my $a1 = shift;
  my $a2 = shift;
  for(my $i = 0; $i < @{$array}; $i += 2) {
    return(1) if($array->[$i] eq $a1 && $array->[$i + 1] eq $a2);
  }
  return(0);
}

1;
