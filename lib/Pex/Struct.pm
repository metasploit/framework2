package Pex::Struct;
use strict;

# -spoon

my $types = {
  'l_u_8'  => [ 'C', \&CharPack, \&CharUnpack, 1, ],
  'l_u_16' => [ 'v', \&DefaultPack, \&DefaultUnpack, 2, ],
  'l_u_32' => [ 'V', \&DefaultPack, \&DefaultUnpack, 4, ],
  'b_u_16' => [ 'n', \&DefaultPack, \&DefaultUnpack, 2, ],
  'b_u_32' => [ 'N', \&DefaultPack, \&DefaultUnpack, 4, ],
  'string' => [ '', \&NoPack, \&NoPack, -1],
};


sub new {
  my $class = shift;
  my $struct = @_ ? shift : [ ];
  my $typedef = @_ ? shift : { };
  my $self = bless({
  }, $class);
  $self->Struct($struct);
  $self->Typedef($typedef);
  return($self);
}

sub StructData {
  my $self = shift;
  $self->{'StructData'} = shift if(@_);
  $self->{'StructData'} = [ ] if(!$self->{'StructData'});
  return($self->{'StructData'});
}

sub Typedefs {
  my $self = shift;
  $self->{'Typedefs'} = shift if(@_);
  $self->{'Typedefs'} = { } if(!$self->{'Typedefs'});
  return($self->{'Typedefs'});
}

sub GetType {
  my $self = shift;
  my $name = shift;
  my $type = $self->Typedefs->{$name};
  if(defined($type)) {
    return($type) if(ref($type) eq 'ARRAY');
    return($types->{$type});
  }
  return($types->{$name});
}

sub Struct {
  my $self = shift;
  my $struct = shift;
  for(my $i = 0; $i < @{$struct}; $i += 2) {
    $self->AddStruct($struct->[$i + 1], $struct->[$i]);
  }
}

sub Typedef {
  my $self = shift;
  my $typedef = shift;
  foreach (keys(%{$typedef})) {
    $self->Typedefs->{$_} = $typedef->{$_};
  }
}

sub AddStruct {
  my $self = shift;
  my $name = shift;
  my $type = shift;
  push(@{$self->StructData}, [ $name, $type, '', ]);
}

sub GetStruct {
  my $self = shift;
  my $name = shift;
  foreach (@{$self->StructData}) {
    return($_) if($_->[0] eq $name);
  }
}

sub Get {
  my $self = shift;

  if(!@_) {
    my $data;
    foreach my $struct (@{$self->StructData}) {
      my $type = $self->GetType($struct->[1]);
      push(@{$data}, [ $struct->[0], $type->[2]($self, $type->[0], $type->[3], $struct->[2]) ]);
    }
    return($data);
  }

  my $name = shift;
  my $struct = $self->GetStruct($name);
  return if(!$struct);
  my $type = $self->GetType($struct->[1]);
  return($type->[2]($self, $type->[0], $type->[3], $struct->[2]));
}
sub GetRaw {
  my $self = shift;
  my $name = shift;
  my $struct = $self->GetStruct($name);
  return if(!$struct);
  return($struct->[2]);
}
sub Set {
  my $self = shift;
  while(@_ >= 2) {
    my $name = shift;
    my $value = shift;
    my $struct = $self->GetStruct($name);
    return if(!$struct);
    my $type = $self->GetType($struct->[1]);
    $struct->[2] = $type->[1]($self, $type->[0], $type->[3], $value);
# size field
    if($struct->[3]) {
      my $struct2 = $self->GetStruct($struct->[3]);
      return if(!$struct2);
      $self->Set($struct2->[0], length($value));
    }
  }
}
sub SetRaw {
  my $self = shift;
  while(@_ >= 2) {
    my $name = shift;
    my $value = shift;
    my $struct = $self->GetStruct($name);
    return if(!$struct);
    $struct->[2] = $value;
# size field
    if($struct->[3]) {
      my $struct2 = $self->GetStruct($struct->[3]);
      return if(!$struct2);
      $self->Set($struct2->[0], length($value));
    }
  }
}

sub SetSizeField {
  my $self = shift;
  my $name = shift;
  my $field = shift;
  my $struct = $self->GetStruct($name);
  return if(!$struct);
  $struct->[3] = $field;
}

sub Fill {
  my $self = shift;
  my $data = shift;

  foreach my $struct (@{$self->StructData}) {
    my $type = $self->GetType($struct->[1]);
    return(0) if(!$type);
    my $length = $type->[3];
    if(!defined($length) || $length < 0) {
      $length = $self->Get($struct->[3]);
    }
    return(0) if(!defined($length) || $length < 0);
    $self->SetRaw($struct->[0], substr($data, 0, $length, ''));
  }

  return(1);
}

sub Fetch {
  my $self = shift;
  my $string;
  foreach my $struct (@{$self->StructData}) {
    $string .= $struct->[2];
  }
  return($string);
}

sub DefaultPack {
  my $self = shift;
  my $type = shift;
  my $size = shift;
  my $data = shift;
  return(pack($type, $data));
}
sub DefaultUnpack {
  my $self = shift;
  my $type = shift;
  my $size = shift;
  my $data = shift;
  return(unpack($type, $data));
}

sub CharPack {
  my $self = shift;
  my $type = shift;
  my $size = shift;
  my $data = shift;
  return(pack($type, chr($data)));
}
sub CharUnpack {
  my $self = shift;
  my $type = shift;
  my $size = shift;
  my $data = shift;
  return(unpack($type, chr($data)));
}

sub NoPack {
  my $self = shift;
  my $type = shift;
  my $size = shift;
  my $data = shift;
  return($data);
}

1;
