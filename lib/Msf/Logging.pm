package Msf::Logging;
use strict;
use base 'Msf::Base';

sub new {
  my $class = shift;
  my $self = bless({
    'Filename' => @_ ? shift : '',
  }, $class);
  return if($self->GetEnv('Logging') && !defined($self->CreateLogDir));
  return($self);
}

sub Filename {
  my $self = shift;
  $self->{'Filename'} = shift if(@_);
  return($self->{'Filename'});
}

sub PrintLine {
  my $self = shift;
  return($self->Print(@_, "\n"));
}

sub Print {
  my $self = shift;
  return if(!$self->GetEnv('Logging'));
  if(ref($self)) {
    if(!$self->SessionPrint(@_)) {
      $self->SetError('[*] Error writing to log: ' . $self->Filename);
    }
  }
  else {
    if(!$self->MainPrint(@_)) {
      $self->SetError('[*] Error writing to main log file.');
    }
  }
}

# Static-ish MainLog stuff

sub MainPrint {
  my $self = shift;
  my $dir = $self->CreateLogDir;
  return(0) if(!defined($dir));

  open(OUTFILE, ">>$dir/msfconsole.log") or return(0);
  print OUTFILE @_;
  close(OUTFILE);
  return(1);
}


sub SessionPrint {
  my $self = shift;
  my $dir = $self->CreateLogDir;
  return(0) if(!defined($dir));
  my $filename = $self->Filename;
  return(0) if(!defined($filename));

  open(OUTFILE, ">>$dir/$filename") or return(0);
  print OUTFILE @_;
  close(OUTFILE);
  return(1);
}

sub CreateLogDir {
  my $self = shift;
  my $dir = $self->GetEnv('LogDir');

  # This is a hack, but since Logging can't import _DotMsfDir...
  if(!defined($dir)) {
    $dir = (($ENV{'HOME'}) ? $ENV{'HOME'} : $self->ScriptBase).'/.msf';
    if (! -d $dir && ! mkdir($dir, 0700)) {
    	return;
    }
    $dir .= '/logs';
  }

  return if(! -d $dir && !mkdir($dir, 0700));
  return($dir);
}

1;








#### 
