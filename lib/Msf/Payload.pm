#!/usr/bin/perl
###############

##
#         Name: Payload.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::Payload;
use strict;
use base 'Msf::Module';

my $defaults =
{
  'Name'        => 'No Name',
  'Version'     => '0.0',
  'Author'      => 'No Author',
  'Arch'        => [ ],
  'OS'          => [ ],
  'Keys'        => [ ],
  'Priv'        => 0,
  'UserOpts'    => { },
  'Refs'        => [ ],
  'Multistage'  => 0,
  'Type'        => '',
  'Description' => 'No Description',
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  my $self = $class->SUPER::new($hash);
  $self->SetDefaults($defaults);
  return($self);
}

# Fall throughs
sub Build {
  my $self = shift;
  return($self->Generate);
}

sub Generate {
  my $self = shift;
  $self->PrintLine('[*] No Generate for this payload: ' , $self->SelfName);
  return;
}


# Keep the old stuff around for doing external payloads
__DATA__
use strict;
use IO::Socket;
use IO::Select;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw();

sub new
{
    my ($cls, $path, $type) = @_;
    
    return undef if ! -f $path;
    return undef if ! -r $path;

    my $self = bless {}, $cls;
    $self->{"PATH"} = $path;
    $self->{"TYPE"} = $type;

    my $res = $self->load();
        
    print STDERR "[*] Error loading payload: " . $self->Error() . "\n" if ! $res;
    return($res);
}

sub set_error
{
    my ($self,$error) = @_;
    my @cinf = caller(1);
    $self->{"ERROR"} = $cinf[3] . " => $error";
}

sub Error
{
    my ($self) = @_;
    return ($self->{"ERROR"});
}

sub load
{
    my ($self) = @_;
    my $res;

    if ($self->{"TYPE"} eq "i")
    {
        $res = $self->load_internal();
    } else {
        $res = $self->load_external();
    }
    return($res);
}

sub load_internal
{
    my ($self) = @_;
    my $options = {};
    my $buffer;
    my $dynpkg = "PexPayload_" . scalar($self);
    $dynpkg =~ s/=|\(|\)//g;
    
    local *TMP;
    
    if (! -f $self->{"PATH"} || ! -r $self->{"PATH"})
    {
        $self->set_error("could not open payload: not a readable file!");
        return undef;   
    }
    
    # open the module file 
    if ( open(TMP, "<" . $self->{"PATH"}) )
    {
        while (<TMP>) { $buffer .= $_;}
        close (TMP);
    } else {
        $self->set_error("could not open payload: $!");
        return undef;
    }
    
    # create a temporary namespace for it
    $buffer = "package " . $dynpkg . ";\nno strict;\n" . $buffer;

    eval($buffer);
    if ($@)
    {
        $self->set_error("load error in payload: " . $self->{"PATH"} . " $@");
        return undef;
    }

    # set the subroutine reference to the generator
    $self->{"generate"} = eval('\&'.$dynpkg.'::generate'); 

    # configure the payload fields
    my $info = eval('$'.$dynpkg.'::payload');

    return($self->config($info));
}


sub load_external
{
    my ($self) = @_;
    my $file = $self->{"PATH"};
    
    if (! -e $file)
    {
        $self->set_error("$file is not executable");
        return(undef);
    }
    
    my $info = ();
    
    local *P;
    if (! open(P, "$file INFO|"))
    {
        $self->set_error("execution of $file failed: $!");
        return(undef)
    }
    
    while (<P>)
    {
        chomp;
        if (m/^OS:(\s+|)(.*)/i)    { $info->{"OS"}   = $2 }
        if (m/^Name:(\s+|)(.*)/i)  { $info->{"Name"} = $2 }
        if (m/^Vers:(\s+|)(.*)/i)  { $info->{"Vers"} = $2 }
        if (m/^Desc:(\s+|)(.*)/i)  { $info->{"Desc"} = $2 }
        if (m/^Auth:(\s+|)(.*)/i)  { $info->{"Auth"} = $2 }
        if (m/^Arch:(\s+|)(.*)/i)  { $info->{"Arch"} = $2 }
        if (m/^Priv:(\s+|)(.*)/i)  { $info->{"Priv"} = $2 }
        if (m/^Keys:(\s+|)(.*)/i)  { $info->{"Keys"} = split(/\s+/, $2) }
        if (m/^Mult:(\s+|)(.*)/i)  { $info->{"Mult"} = $2 }
        if (m/^Size:(\s+|)(.*)/i)  { $info->{"Size"} = $2 }
        if (m/^Type:(\s+|)(.*)/i)  { $info->{"Type"} = $2 }
        if (m/^Opts:(\s+|)([\w]+)(\s+)([\w]+)(\s+)([\w]+)(\s+)(.*)/)
        {
            my ($oname, $oreqd, $otype, $odesc) = ($2, $4, $6, $8);
            $info->{"Opts"}->{$oname} = [$oreqd, $otype, $odesc];
        }
    }
    close(P);
    
    return($self->config($info));
}


sub config
{
    my ($self, $info) = @_;

    foreach my $var (qw{OS Name Vers Desc Arch Auth Priv Keys Mult Size Type Opts})
    {
        if (! exists($info->{$var}))
        {
            $self->set_error("missing parameter: $var");
            return(undef);
        }
        $self->{$var} = $info->{$var}
    }
    return($self);
}

sub OS   { my $self = shift; return $self->{"OS"} }
sub Name { my $self = shift; return $self->{"Name"} }
sub Vers { my $self = shift; return $self->{"Vers"} }
sub Desc { my $self = shift; return $self->{"Desc"} }
sub Auth { my $self = shift; return $self->{"Auth"} }
sub Arch { my $self = shift; return $self->{"Arch"} }
sub Priv { my $self = shift; return $self->{"Priv"} }
sub Keys { my $self = shift; return $self->{"Keys"} }
sub Mult { my $self = shift; return $self->{"Mult"} }
sub Size { my $self = shift; return $self->{"Size"} }
sub Type { my $self = shift; return $self->{"Type"} }
sub Opts { my $self = shift; return $self->{"Opts"} }

sub Build
{
    my ($self, $args) = @_;
        
    if ($self->{"TYPE"} eq "i")
    {
        return($self->{"generate"}->($args));
    } else {
    
        local *P;
        my $file = $self->{"PATH"};
        my $opt_str;
        
        # XXX - shell metacharacters in the option string will cause problems
        foreach (keys(%{$args})) { $opt_str.= " $_=".$args->{$_} }

        if (! open(P, "$file BUILD $opt_str|"))
        {
            $self->set_error("execution of $file failed: $!");
            return(undef)
        }

        my $res;
        while (<P>) { $res .= $_ }
        close (P);
        return($res);
    }
}

sub Validate
{
    my ($self, $inp) = @_;

    foreach my $o ( keys( %{ $self->{Opts} } ) )
    {
        
        my ($req, $type, $dflt) = @{$self->{Opts}->{$o}};
        my $data = $inp->{$o};
        my $dflt;
        
        # automatically set default values for required options
        if ($req && ! exists($inp->{$o}))
        {
            if (! defined($dflt))
            {
                $self->set_error("Missing required option $o");
                return(0);
            } else { $inp->{$o} = $dflt }
        }

        if (defined($data) && $type eq "ADDR")
        {
            my $baddr = gethostbyname($data);
            if (! $baddr)
            {
                $self->set_error("Invalid address for option $o");
                return(0);
            }
        }

        if (defined($data) && $type eq "PORT" && ($data <1 || $data > 65535))
        {
            $self->set_error("Invalid port for option $o");
            return(0);            
        }

        if (defined($data) && $type eq "BOOL" && $data !~ /^(y|n|t|f|0|1)/i)
        {
            $self->set_error("Invalid boolean for option $o");
            return(0);
        }
        
        if (defined($data) && $type eq "PATH" && ! -r $data)
        {
            $self->set_error("Invalid path for option $o");
            return(0);        
        }   
    }

    return(1);
}

sub Advanced {
  return;
}
1;
