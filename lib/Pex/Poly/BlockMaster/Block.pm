package Pex::Poly::BlockMaster::Block;
use strict;
use Pex::Text;

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
  foreach my $dep (@{$self->_Depers}) {
    $dep->_ClearState;
  }
}
sub _SetupBlocks {
  my $self = shift;
  my $badChars = shift;
  my $blocks = [ ];

  foreach my $block (@{$self->_IBlocks}) {
    my $tblock = $block;
    $tblock =~ s/\[\>.*?\<\]//g;
    if(!Pex::Text::BadCharCheck($badChars, $tblock)) {
      push(@{$blocks}, $block);
    }
  }
  if(!@{$blocks} && @{$self->_IBlocks}) {
    push(@{$blocks}, $self->_IBlocks->[0]);
  }
  $self->_Blocks($blocks);
 
  foreach my $dep (@{$self->_Depers}) {
    $dep->_SetupBlocks($badChars);
  }
}

sub Name {
  my $self = shift;
  $self->{'Name'} = shift if(@_);
  return($self->{'Name'});
}

sub _Deps {
  my $self = shift;
  $self->{'_Deps'} = shift if(@_);
  $self->{'_Deps'} = [ ] if(ref($self->{'_Deps'}) ne 'ARRAY');
  return($self->{'_Deps'});
}
sub _Depers {
  my $self = shift;
  $self->{'_Depers'} = shift if(@_);
  $self->{'_Depers'} = [ ] if(ref($self->{'_Depers'}) ne 'ARRAY');
  return($self->{'_Depers'});
}

sub _IBlocks {
  my $self = shift;
  $self->{'_IBlocks'} = shift if(@_);
  $self->{'_IBlocks'} = [ ] if(ref($self->{'_IBlocks'}) ne 'ARRAY');
  return($self->{'_IBlocks'});
}
sub _Blocks {
  my $self = shift;
  $self->{'_Blocks'} = shift if(@_);
  $self->{'_Blocks'} = [ ] if(ref($self->{'_Blocks'}) ne 'ARRAY');
  return($self->{'_Blocks'});
}

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

sub NextBlock {
  my $self = shift;
  if($self->_Done) {
    foreach my $dep (@{$self->_Depers}) {
      my $next = $dep->NextBlock;
      return($next) if($next);
    }
  }
  else {
    return($self) if($self->CanBuild);
  }
  return;
}

1;
