#!/usr/bin/perl
###############

##
#         Name: CommandPayload.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::CommandPayload;
use strict;
use base 'Msf::Payload';

sub new {
    my $class = shift;
    my $hash = @_ ? shift : { };
    my $self = $class->SUPER::new($hash);
    return($self);
}

sub Size {
    my $self = shift;
    my $data = $self->Build();
    return(length($data));
}

sub Build {
    my $self = shift;
    my $cmds = $self->{'Info'}->{'CommandPayload'};
    my $newc = $cmds;
    my @vars;
        
    # extract all tokens from the command string
    foreach my $chunk (split(/\[\>/, $cmds))
    {
        if ($chunk =~ m/^([^\<]+)\<\]/)
        {
            my $varname = $1;
            push @vars, $varname;
            if (my $val = $self->GetVar($varname))
            {
                $newc =~ s/\[\>$varname\<\]/$val/g;
            }
        }
    }
    return $newc;
}

1;
