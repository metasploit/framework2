#####     #####
## Col Print ##
#####     #####

# Author: spoonm <ninjatools [at] hush.com>
# This file is not original to the Metasploit project, but to another.
# Use in Metasploit Exploit Framework falls under the package's license.

package Msf::ColPrint;
use strict;

sub new {
  return(bless(
    {
      __PACKAGE__.'data' => [ ],
      __PACKAGE__.'maxLen' => [],
      __PACKAGE__.'totalMaxLen' => '',
      __PACKAGE__.'initIndent' => $_[1] || 0,
      __PACKAGE__.'pad' => $_[2] || 2,
    }, shift)
  );
}

###
# Internals
###
sub _data {
  my $self = shift;
  $self->{__PACKAGE__.'data'} = shift if(@_);
  return($self->{__PACKAGE__.'data'});
}
sub _maxLen {
  my $self = shift;
  $self->{__PACKAGE__.'maxLen'} = shift if(@_);
  return($self->{__PACKAGE__.'maxLen'});
}
sub _totalMaxLen {
  my $self = shift;
  my $length = 0;
  foreach (@{$self->_maxLen}) {
    $length += $_ + $self->_pad;
  }
  $length -= $self->_pad if($length);
  return($length);
}

  
sub _initIndent {
  my $self = shift;
  $self->{__PACKAGE__.'initIndent'} = shift if(@_);
  return($self->{__PACKAGE__.'initIndent'});
}
sub _pad {
  my $self = shift;
  $self->{__PACKAGE__.'pad'} = shift if(@_);
  return($self->{__PACKAGE__.'pad'});
}


###
# Add'ers
###
sub AddRow {
  my $self = shift;
  my $maxLen = $self->_maxLen;
  push(@{$self->_data}, [ 'Row', @_ ]);
  my $total = 0;
  for(my $i = 0; $i < @_; $i++) {
    my $length = length($_[$i]);
    $maxLen->[$i] = $length if($length > $maxLen->[$i]);
  }
}
sub AddHr {
  my $self = shift;
  my $char = @_ ? shift : '-';
  push(@{$self->_data}, [ 'Hr', $char ]);
}

sub AddData {
  my $self = shift;
  my $data = shift;
  push(@{$self->_data}, [ 'Data', $data ]);
}

###
# Get'ers
###
sub GetOutput {
  my $self = shift;
  my $output;
  foreach (@{$self->_data}) {
    my $type = shift(@$_);
    if($type eq 'Data') {
      $output .= shift(@$_);
      next;
    }
    $output .= " " x $self->_initIndent;
    if($type eq 'Hr') {
      $output .= shift(@$_) x $self->_totalMaxLen . "\n";
      next;
    }

    for(my $i = 0; $i < @{$_}; $i++) {
      my $cell = $_->[$i];
      if($cell eq '__hr__') {
        $output .= "-" x $self->_maxLen->[$i] . " " x $self->_pad;
        next;
      }
      $output .= $cell;
      # Don't add pad if its the last column.
      if($i < @{$_} - 1) {
        $output .= " " x ($self->_maxLen->[$i] - length($cell) + $self->_pad);
      }
    }
    $output .= "\n";
  }
  return($output);
}

1;
