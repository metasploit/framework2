package Msf::Config;
use base 'Msf::Base';

use strict;
use FindBin qw{$Bin};

my $defaults = {
  'Encoder' => 'Msf::Encoder::Pex',
  'Nop'     => 'Msf::Nop::Pex',
  'DebugLevel' => 5,
  'Logging' => 'Enabled',
};

my %AddrCache;
my $ConfigDir;

sub new {
    my $class = shift;
    my $self  = bless {}, $class;
    
    $self->{'ConfigDir'} = shift || do
    {
        $self->{'ConfigDir'} = exists($ENV{'HOME'}) ? $ENV{'HOME'} : $Bin;
        $self->{'ConfigDir'} .= "/.msfconfig";
    };
    
    $self->LoadConfig;
    return $self;
}

sub ConfigDir {
    my $self = shift;
    my $dir  = shift;
    
    if (! $dir) { return $self->{'ConfigDir'} }
    
    if (! -d $dir && mkdir($dir, 0700) && ! -d $dir)
    {
        $self->PrintLine("Msf::Config: Could not access configuration directory '$dir' ($!)");
        return(undef);
    }
    $self->{'ConfigDir'} = $dir;
    return($dir);
}

sub LoadConfig {
    my $self = shift;
    my $dir  = $self->{'ConfigDir'};

    my $tmpenv = { };
    local *X;
    
    # Load default values into the environment hash
    foreach (keys(%{$defaults})) { $self->SetGlobalEnv($_, $defaults->{$_}) }
    
    # Look for directory, try to create, make sure it exists
    if (! -d $dir && mkdir($dir, 0700) && ! -d $dir)
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
                if (m/^([G|T])\s+([^\s+]*)\s+(.*)/) 
                {
                    my ($eType, $eName, $eValue) = ($1, $2, $3);
                    
                    # G     Var   Value
                    if ($eType eq "G")
                    {
                        $self->SetGlobalEnv($eName, $eValue);
                    }
                    
                    # T     Msf::Exploit::NastyRemoteOverflow=Var   Value
                    if ($eType eq "T" && $eName =~ /^([^\=]*)=(.*)/) 
                    {
                        $tmpenv->{$1}->{$2} = $eValue;
                    }
                }
            }
            $self->_TempEnvs($tmpenv);
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
            
            my $environs = $self->GetTempEnvs;
            foreach my $env (keys(%{$environs}))
            {
                foreach my $var (keys(%{$environs->{$env}}))
                {
                    print X "T\t". $env ."=". $var ."\t". $environs->{$env}->{$var} ."\n";
                }
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


sub AddrCacheAdd {
    my $self = shift;
    my $addr = shift;
    $self->{'AddrCache'}->{$addr}++;
}

sub AddrCacheDel {
    my $self = shift;
    my $addr = shift;
    delete($self->{'AddrCache'}->{$addr});
}

sub AddrCache {
    my $self = shift;
    return keys(%{$self->{'AddrCache'}});
}

1;
