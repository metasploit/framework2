package Pex::Struct;
use strict;

# -spoon

my $types = {
   #          size, packfunc, unpackfunc, @dataToSendToFuncs
  'u_8'    => [ 1, \&DefaultPack, \&DefaultUnpack, 'C', ],
  'l_u_16' => [ 2, \&DefaultPack, \&DefaultUnpack, 'v', ],
  'l_u_32' => [ 4, \&DefaultPack, \&DefaultUnpack, 'V', ],
  'b_u_16' => [ 2, \&DefaultPack, \&DefaultUnpack, 'n', ],
  'b_u_32' => [ 4, \&DefaultPack, \&DefaultUnpack, 'N', ],
  'struct' => [ undef, \&NoPack, \&NoPack, ],
  'string' => [ undef, \&NoPack, \&NoPack, ],
};


sub new {
  my $class = shift;
  my $struct = @_ ? shift : [ ];
  my $typedef = @_ ? shift : { };
  my $self = bless({
  }, $class);
  $self->AddStructs(@{$struct});
  $self->AddTypedefs(%{$typedef});
  return($self);
}

sub copy {
  my $self = shift;
  return(bless($self->copyFooHash($self)));
}

sub copyFooHash {
  my $self = shift;
  my $hash = shift;
  my %newHash = %{$hash};
  foreach (keys(%newHash)) {
    if(ref($newHash{$_}) eq 'HASH') {
      $newHash{$_} = $self->copyFooHash($newHash{$_});
    }
    elsif(ref($newHash{$_}) eq 'ARRAY') {
      $newHash{$_} = $self->copyFooArray($newHash{$_});
    }
  }
  return(\%newHash);
}

sub copyFooArray {
  my $self = shift;
  my $array = shift;
  my @newArray = @{$array};
  for(my $i = 0; $i < @newArray; $i++) {
    if(ref($newArray[$i]) eq 'HASH') {
      $newArray[$i] = $self->copyFooHash($newArray[$i]);
    }
    elsif(ref($newArray[$i]) eq 'ARRAY') {
      $newArray[$i] = $self->copyFooArray($newArray[$i]);
    }
  }
  return(\@newArray);
}
  

sub newC {
  my $class = shift;
  my $struct = @_ ? shift : [ ];
  my $typedef = @_ ? shift : { };
  my $self = bless({
  }, $class);
  $self->AddStructsC(@{$struct});
  $self->AddTypedefs(%{$typedef});
  return($self);
}

sub _StructData {
  my $self = shift;
  $self->{'StructData'} = shift if(@_);
  $self->{'StructData'} = [ ] if(!$self->{'StructData'});
  return($self->{'StructData'});
}

sub _GetStructData {
  my $self = shift;
  my $name = shift;
  foreach (@{$self->_StructData}) {
    return($_) if($_->{'Name'} eq $name);
  }
}
sub _RecursiveGetStructData {
  my $self = shift;
  my $name = shift;
  foreach (@{$self->_StructData}) {
    if($_->{'Type'} eq 'struct') {
      my $struct = $_->{'Data'}->_RecursiveGetStructData($name);
      return($struct) if($struct);
    }
    else {
      return($_) if($_->{'Name'} eq $name);
    }
  }
}

sub _Typedefs {
  my $self = shift;
  $self->{'Typedefs'} = shift if(@_);
  $self->{'Typedefs'} = { } if(!$self->{'Typedefs'});
  return($self->{'Typedefs'});
}

sub _GetType {
  my $self = shift;
  my $name = shift;
  my $type = $self->_Typedefs->{$name};
  if(defined($type)) {
    return($type) if(ref($type) eq 'ARRAY');
    $type = $types->{$type};
  }
  else {
    $type = $types->{$name};
  }

  if(ref($type) ne 'ARRAY') {
    die("Cannot find a native type for $name");
  }
  return($type);
}

sub AddStructs {
  my $self = shift;
  while(@_ >= 2) {
    my $name = shift;
    my $type = shift;
#fixme 
#   if($self->_RecursiveGetStructData($name)) {
#     die("Name collision: $name");
#   }
    push(@{$self->_StructData}, { 'Name' => $name, 'Type' => $type });
  }
}
sub AddStructsC {
  my $self = shift;
  while(@_ >= 2) {
    my $type = shift;
    my $name = shift;
    $self->AddStructs($name, $type);
  }
}

sub AddTypedefs {
  my $self = shift;
  while(@_ >= 2) {
    my $newType = shift;
    my $type = shift;
    $self->_Typedefs->{$newType} = $type;
  }
}

sub Get {
  my $self = shift;
  if(!@_) {
    my $data;
    foreach my $struct (@{$self->_StructData}) {
      push(@{$data}, [ $struct->{'Name'}, $self->_Unpack($struct, $struct->{'Data'}) ]);
    }
    return($data);
  }

  my $name = shift;
  my $struct = $self->_GetStructData($name);
  return if(!$struct);
  return($self->_Unpack($struct, $struct->{'Data'}));
}

sub RecursiveGet {
  my $self = shift;

  if(!@_) {
    my $data;
    foreach my $struct (@{$self->_StructData}) {
      if($struct->{'Type'} eq 'struct') {
        push(@{$data}, @{$struct->{'Data'}->Get});
      }
      else {
        push(@{$data}, [ $struct->{'Name'}, $self->Get($struct->{'Name'}) ]);
      }
    }
    return($data);
  }

  my $name = shift;
  my $struct = $self->_GetStructData($name);
  if(!$struct) {
    foreach my $struct (@{$self->_StructData}) {
      if($struct->{'Type'} eq 'struct') {
        my $value = $struct->{'Data'}->RecursiveGet($name);
        return($value) if(defined($value));
      }
    }
    return;
  }
  else {
    return($self->Get($struct->{'Name'}));
  }
}

sub _Unpack {
  my $self = shift;
  my $struct = shift;
  my $data = shift;
  return if(!$struct);
  my $type = $self->_GetType($struct->{'Type'});
  return if(!$type);

  return($type->[2]($self, $type->[0], $data, @{$type}[3 .. @{$type} - 1]));
}

sub _Pack {
  my $self = shift;
  my $struct = shift;
  my $data = shift;
  return if(!$struct);
  my $type = $self->_GetType($struct->{'Type'});
  return if(!$type);

  return($type->[1]($self, $type->[0], $data, @{$type}[3 .. @{$type} - 1]));
}

sub GetRaw {
  my $self = shift;
  my $name = shift;
  my $struct = $self->_GetStructData($name);
  return if(!$struct);
  return($struct->{'Data'});
}

sub Set {
  my $self = shift;
  while(@_ >= 2) {
    my $name = shift;
    my $value = shift;
    my $struct = $self->_GetStructData($name);
    next if(!$struct);
    $struct->{'Data'} = $self->_Pack($struct, $value);
    $self->_UpdateSize($struct->{'Name'});
  }
}

sub SetRaw {
  my $self = shift;
  while(@_ >= 2) {
    my $name = shift;
    my $value = shift;
    my $struct = $self->_GetStructData($name);
    next if(!$struct);
    $struct->{'Data'} = $value;
    $self->_UpdateSize($name);
  }
}

sub SetSizeField {
  my $self = shift;
  while(@_ >= 2) {
    my $name = shift;
    my $field = shift;
    my $struct = $self->_GetStructData($name);
    next if(!$struct);
    $struct->{'SizeField'} = $field;
  }
}

sub SetSize {
  my $self = shift;
  while(@_ >= 2) {
    my $name = shift;
    my $size = shift;
    my $struct = $self->_GetStructData($name);
    next if(!$struct);
    $struct->{'Size'} = $size;
  }
}

sub _UpdateSize {
  my $self = shift;
  my $name = shift;
  my $struct = $self->_GetStructData($name);
  return if(!$struct);
  if($struct->{'SizeField'}) {
    $self->Set($struct->{'SizeField'}, length($struct->{'Data'}));
  }
}

sub UpdateSizes {
  my $self = shift;
  my @names = @_;

  if(!@names) {
    foreach my $struct (@{$self->_StructData}) {
      $self->_UpdateSize($struct->{'Name'});
    }
  }

  else {
    foreach my $name (@names) {
      $self->_UpdateSize($name);
    }
  }
}


#sub _UpdateSize {
#  my $self = shift;
#  my $name = shift;
#
#  my $struct = $self->_GetStructData->($name);
#  return if(!$struct);
#
#  if($struct->{'SizeField'}) {
#    my $size = 0;
#    foreach $field (@{$struct->{'SizeFields'}}) {
#      $size .= $self->Get($field);
#    }
#    $self->Set($struct->{'Name'}, $size);
#  }
#}


sub Fill {
  my $self = shift;
  my $data = shift;

  foreach my $struct (@{$self->_StructData}) {
    if($struct->{'Type'} eq 'struct') {
      $struct->{'Data'}->Fill($data);
      $data = $struct->{'Data'}->LeftOver;
    }
    else {
      my $length = $self->_Length($struct->{'Name'});
      return(0) if(!defined($length));
      $self->SetRaw($struct->{'Name'}, substr($data, 0, $length, ''));
    }
  }
  $self->{'LeftOver'} = $data;
  return(1);
}


sub _Length {
  my $self = shift;
  my $name = shift;
  my $struct = $self->_GetStructData($name);
  return if(!$struct);

  my $length = $struct->{'Size'};
  if(!defined($length) && $struct->{'SizeField'}) {
    $length = $self->Get($struct->{'SizeField'});
  }

  if(!defined($length)) {
    my $type = $self->_GetType($struct->{'Type'});
    return if(!$type);
  
    $length = $type->[0];
  }
  
  return if(!defined($length));
  return($length);
}


sub Fetch {
  my $self = shift;
  my $string;
  foreach my $struct (@{$self->_StructData}) {
    if($struct->{'Type'} eq 'struct') {
      $string .= $struct->{'Data'}->Fetch;
    }
    else {
      $string .= $self->GetRaw($struct->{'Name'});
    }
  }
  return($string);
}

sub LeftOver {
  my $self = shift;
  return($self->{'LeftOver'});
}

sub Size {
  my $self = shift;
  return(length($self->Fetch));
}

sub Length {
  my $self = shift;
  return($self->Size);
}


sub DefaultPack {
  my $self = shift;
  my $size = shift;
  my $data = shift;
  my $type = shift;
  return(pack($type, $data));
}
sub DefaultUnpack {
  my $self = shift;
  my $size = shift;
  my $data = shift;
  my $type = shift;
  return(unpack($type, $data));
}
sub NoPack {
  my $self = shift;
  my $size = shift;
  my $data = shift;
  my $type = shift;
  return($data);
}

sub StructPack {
  my $self = shift;
  my $size = shift;
  my $data = shift;
  return($data);
}

1;
