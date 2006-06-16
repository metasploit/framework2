package Pex::Poly::BlockMaster::Block;
use strict;
use Pex::Text;
use Pex::Utils;

sub new {
  my $class = shift;
  my $self = bless({ }, $class);
  $self->_ClearState;
  $self->Name(@_ ? shift : $self);
  $self->AddBlock(@_) if(@_);
  return($self);
}

sub _ClearState {
  my $self = shift;
  $self->_Done(0);
}

# This is where we iterate through the IBlocks (this is the Inital Blocks of
# possible data) and check for bad characters, and build a new block list
# for _Blocks.
sub _BuildInit {
  my $self = shift;
  my $badChars = shift;

  # clear myself
  $self->_ClearState;

  my $blocks = [ ];

  foreach my $block (@{$self->_IBlocks}) {
    my $tblock = $block;
    $tblock =~ s/\[\>.*?\<\]//g;
    if(!Pex::Text::BadCharCheck($badChars, $tblock)) {
      push(@{$blocks}, $block);
    }
  }
  # If no blocks worked, just use the first one (even though it's bad), and
  # well, hope for the best :\
  if(!@{$blocks} && @{$self->_IBlocks}) {
    push(@{$blocks}, $self->_IBlocks->[0]);
  }

  $self->_Blocks($blocks);
 
  # Cascade down through the dependents
  foreach my $dep (@{$self->_Depers}) {
    $dep->_BuildInit($badChars);
  }
}

sub Name {
  my $self = shift;
  $self->{'Name'} = shift if(@_);
  return($self->{'Name'});
}

# Dependencies
sub _Deps {
  my $self = shift;
  $self->{'_Deps'} = shift if(@_);
  $self->{'_Deps'} = [ ] if(ref($self->{'_Deps'}) ne 'ARRAY');
  return($self->{'_Deps'});
}

# Dependents
sub _Depers {
  my $self = shift;
  $self->{'_Depers'} = shift if(@_);
  $self->{'_Depers'} = [ ] if(ref($self->{'_Depers'}) ne 'ARRAY');
  return($self->{'_Depers'});
}

# Inital blocks
sub _IBlocks {
  my $self = shift;
  $self->{'_IBlocks'} = shift if(@_);
  $self->{'_IBlocks'} = [ ] if(ref($self->{'_IBlocks'}) ne 'ARRAY');
  return($self->{'_IBlocks'});
}

# Blocks prepared for the current Build()
sub _Blocks {
  my $self = shift;
  $self->{'_Blocks'} = shift if(@_);
  $self->{'_Blocks'} = [ ] if(ref($self->{'_Blocks'}) ne 'ARRAY');
  return($self->{'_Blocks'});
}

# Done bit
sub _Done {
  my $self = shift;
  $self->{'_Done'} = shift if(@_);
  return($self->{'_Done'});
}

sub _AddDeps {
  my $self = shift;
  push(@{$self->_Deps}, @_);
}
sub _AddDepers {
  my $self = shift;
  push(@{$self->_Depers}, @_);
}
sub AddBlock {
  my $self = shift;
  push(@{$self->_IBlocks}, @_);
}

sub NumBlocks {
  my $self = shift;
  return(scalar(@{$self->_IBlocks}));
}

sub Signature {
  my $self = shift;
  return($self->NumBlocks . ' - ' . $self->Name);
}

sub _Connections {
  my $self = shift;
  my @conns;
  foreach my $dep (@{$self->_Depers}) {
    push(@conns, $self->Signature, $dep->Signature);
    push(@conns, $dep->_Connections);
  }
  return(@conns);
}

sub AddDepend {
  my $self = shift;
  foreach my $dep (@_) {
    $self->_AddDeps($dep);
    $dep->_AddDepers($self);
  }
}

# true if all of our dependencies are finished
sub CanBuild {
  my $self = shift;
  foreach my $dep (@{$self->_Deps}) {
    return(0) if(!$dep->_Done);
  }
  return(1);
}

sub Build {
  my $self = shift;
  $self->_Done(1);
  return($self->RandBlock);
}

sub RandBlock {
  my $self = shift;
  return if(!@{$self->_Blocks});
  my $rand = int(rand(@{$self->_Blocks}));
  return($self->_Blocks->[$rand]);
}

sub _TopNextBlock {
  my $self = shift;
  if(!$self->_Done) {
    return($self);
  }
  else {
    my $ready = [ ];
    foreach my $dep (@{$self->_Depers}) {
      foreach my $r ($dep->_ReadyBlocks) {
        push(@{$ready}, $r) if(!Pex::Utils::ArrayContains($ready, [ $r ]));
      }
    }
    return if(!@{$ready});
    return($ready->[int(rand(@{$ready}))]);
  }
  return;
}

# Returns the ready blocks, could very well have duplicates, but this will
# be sorted out by _TopNextBlock
sub _ReadyBlocks {
  my $self = shift;
  if(!$self->_Done) {
    return($self) if($self->CanBuild);
    # if we aren't done, and also aren't ready, then just return
  }
  else {
    my @r;
    foreach my $dep (@{$self->_Depers}) {
      push(@r, $dep->_ReadyBlocks);
    }
    return(@r);
  }
  return;
}

sub NextBlock {
  my $self = shift;
#  print "!! NextBlock called on " . $self->Name . "\n";
  if($self->_Done) {
    my @depers = @{$self->_Depers};
    Pex::Utils::FisherYates(\@depers);
#    foreach my $dep (@depers) {
#      print $dep->Name . ',';
#    }
#    print "\n";
    foreach my $dep (@depers) {
#      print "** " . $self->Name . " -> " . $dep->Name . "\n";
      my $next = $dep->NextBlock;
      return($next) if($next);
    }
  }
  else {
#    print "Returning self?\n";
    return($self) if($self->CanBuild);
    # if we fall through here, and then return nothing, it means that we
    # were not ready to build ourselves (have unfinished dependencies).  The
    # cascading will then moving from the higher up blocks on, and hopefully
    # finish this dependency.
  }
  return;
}

1;
