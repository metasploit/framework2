package Msf::Config;
use base 'Msf::Base';

use strict;
use FindBin qw{$Bin};

my $defaults = {
  'Encoder' => 'Msf::Encoder::Pex',
  'Nop'     => 'Msf::Nop::Pex',
  'DebugLevel' => 0,
  'Logging' => 'Enabled',
};

my %AddrCache;
my $ConfigDir;

sub new {
    my $class = shift;
    my $dir   = shift || do 
    {
        $dir = exists($ENV{'HOME'})) ? $ENV{'HOME'} : $Bin;
        $dir .= "/.msfconfig";
    };
    
    $self->{'ConfigDir'} = $dir;
    $self->LoadConfig;
    return $self;
}

sub ConfigDir {
    my $self = shift;
    my $dir  = shift;
    
    if (! -d $dir && mkdir(0700, $dir) && ! -d $dir)
    {
        $self->PrintLine("Msf::Config: Could not access configuration directory '$dir' ($!)");
        return FALSE;
    }
    return TRUE;
}

sub LoadConfig {
    my $self = shift;
    my $dir  = $self->{'ConfigDir'};

    my $conf = { };
    local *X;
    
    # Load default values into the environment hash
    foreach (keys(%{$defaults})) { $conf->{'G'}->{$_} = $defaults->{$_} }  
    
    # Look for directory, try to create, make sure it exists
    if (! -d $dir && mkdir(0700, $dir) && ! -d $dir)
    {
        # Could not create config directory from one reason or another
        $self->PrintLine("Msf::Config: Could not access configuration directory '$dir' ($!)");
    } else {
        
        # Read the [G]lobal and [T]emporary Environments
        if (-r "$dir/environ" && open(X, "<$dir/environ"))
        {
            while (<X>) 
            {
                chomp;
                next if /^#/;
                if (m/^([G|T])\s+([^\s+]*)\s+(.*)/) { $conf->{$1}->{$2} = $3 }
            }
            close (X);
        }
        
        # Load the address cache if it exists 
        if (-r "$dir/addrcache" && open(X, "<$dir/addrcache"))
        {
            while (<X>)
            {
                chomp;
                $self->{'AddrCache'}->{$_}++;
            }
            close (X);
        }
    }
    
    foreach (keys(%{$conf->{'G'}})) { $self->SetGlobalEnv($_, $conf->{'G'}->{$_}) }
    foreach (keys(%{$conf->{'T'}})) { $self->SetTempEnv($_, $conf->{'T'}->{$_}) }
}

sub SaveConfig {
    my $self = shift;
    my $dir  = $self->{'ConfigDir'};

    my $conf = { };
    local *X;
    
    # Look for directory, try to create, make sure it exists
    if (! -d $dir && mkdir(0700, $dir) && ! -d $dir)
    {
        # Could not create config directory from one reason or another
        $self->PrintLine("Msf::Config: Could not access configuration directory '$dir' ($!)");
    } else {
        
        # Write the [G]lobal and [T]emporary Environments
        if (open(X, ">$dir/environ"))
        {
            foreach (keys(%{$self->GetGlobalEnv}))
            {
                print X "G\t$_\t".$self->GetGlobalEnv($_)."\n";
            }
            
            foreach (keys(%{$self->GetTempEnv}))
            {
                print X "T\t$_\t".$self->GetTempEnv($_)."\n";
            }
            
            close (X);        
        }
        
        # Save the address cache if it exists 
        if (scalar(keys(%{$self->{'AddrCache'}})) && open(X, ">$dir/addrcache"))
        {
            print X join("\n", keys(%{$self->{'AddrCache'}}));
            close (X);
        }
    }
}



1;
__DATA__
sub PopulateConfig {
  my $self = shift;
  my $configFile = shift;
  my ($globalEnv, $tempEnvs) = $self->ReadConfig($configFile);
  $self->SetGlobalEnv(%{$self->MergeHash($globalEnv, $defaults)});

  $self->SaveTempEnv('_Save');
  $self->UnsetTempEnv;
  foreach my $tempEnv (keys %{$tempEnvs}) {
    $self->SetTempEnv(%{$tempEnvs->{$tempEnv}});
    $self->SaveTempEnv($tempEnv);
    $self->UnsetTempEnv;
  }
  $self->LoadTempEnv('_Save');
  $self->DeleteTempEnv('_Save');
}

sub SaveConfig {
  my $self = shift;
  my $configFile = shift;
  $self->WriteConfig($configFile, $self->GetEnv);
}

sub ReadConfig {
  my $self = shift;
  my $configFile = shift;
  my $globalEnv = { };
  my $tempEnvs = { };
  my $env = $globalEnv;
  open(INFILE, "<$configFile") or return($globalEnv, $tempEnvs);
  while(<INFILE>) {
    s/\r//g;
    chomp;
    next if(/^\w*#/);
    if(/^(.*?)=(.*)/) {
      $env->{$1} = $2;
    }
    elsif(/^(.*?):/) {
      $tempEnvs->{$1} = { };
      $env = $tempEnvs->{$1};
    }
  }
  close(INFILE);
  return($globalEnv, $tempEnvs);
}

#fixme needs to be updated for temp envs
sub WriteConfig {
  my $self = shift;
  my $configFile = shift;
  my %config = @_;
  open(OUTFILE, ">$configFile") or return;
  foreach (keys(%config)) {
    print OUTFILE "$_=$config{$_}\n";
  }
  close(OUTFILE);
}

1;
