package Pex::Poly::BlockMaster::Block;
use strict;

sub new {
  my $class = shift;
  my $self = bless({ }, $class);
  $self->_Done(0);
  $self->AddBlock(@_) if(@_);
  return($self);
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
  push(@{$self->_Blocks}, @_);
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
