##
#         Name: Pex::RawPackets
#       Author: H D Moore <hdm [at] metasploit.com>
#    Copyright: H D Moore / METASPLOIT.COM
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##


package Pex::RawPackets;
use NetPacket::IP   ":ALL";
use NetPacket::TCP  ":ALL";
use NetPacket::UDP  ":ALL";
use NetPacket::ICMP ":ALL";
use strict;


sub new {
    my $cls = shift;
    my $arg = shift || "IP";
    my $obj = bless {}, $cls;
    
    if (! $obj->can($arg)) 
    {
        print STDERR "Net::RawPackets: no method defined for type $arg\n";
        return undef;
    }
    
    $obj->$arg;
    return $obj;
}


sub IP {
    my $self = shift;
    
    my $rpkt = NetPacket::IP->decode();   
    $rpkt->{ver}        = IP_VERSION_IPv4;
    $rpkt->{hlen}       = 5;
    $rpkt->{id}         = (rand() * 65535);
    $rpkt->{proto}      = IP_PROTO_IP;
    $rpkt->{ttl}        = 255;
    $rpkt->{src_ip}     = "127.0.0.1";
    $rpkt->{dest_ip}    = "127.0.0.1";
    $rpkt->{tos}        = 0;
    $rpkt->{len}        = 0;
    $rpkt->{options}    = "";
    $rpkt->{foffset}    = 0;
    $rpkt->{flags}      = 0;
    
    $self->{'TYPE'} = 'IP';
    $self->{'IP'}   = $rpkt;
}


sub TCP {
    my $self = shift;
    
    my $rpkt = NetPacket::IP->decode();   
    $rpkt->{ver}        = IP_VERSION_IPv4;
    $rpkt->{hlen}       = 5;
    $rpkt->{id}         = (rand() * 65535);
    $rpkt->{proto}      = IP_PROTO_TCP;
    $rpkt->{ttl}        = 255;
    $rpkt->{src_ip}     = "127.0.0.1";
    $rpkt->{dest_ip}    = "127.0.0.1";
    $rpkt->{tos}        = 0;
    $rpkt->{len}        = 0;
    $rpkt->{options}    = "";
    $rpkt->{foffset}    = 0;
    $rpkt->{flags}      = 0;
    
    my $tpkt = NetPacket::TCP->decode();
    $tpkt->{src_port}   = 0;
    $tpkt->{dest_port}  = 0;
    $tpkt->{seqnum}     = 0;
    $tpkt->{acknum}     = 0;
    $tpkt->{flags}      = 0;
    $tpkt->{winsize}    = 512;
    $tpkt->{cksum}      = 0;
    $tpkt->{urg}        = 0;
    $tpkt->{options}    = "";
    $tpkt->{hlen}       = 5;
    $tpkt->{reserved}   = 0;
    $tpkt->{data}       = "";

    $self->{'TYPE'} = 'TCP';
    $self->{'IP'}   = $rpkt;
    $self->{'TCP'}  = $tpkt;
}

sub UDP {
    my $self = shift;
    
    my $rpkt = NetPacket::IP->decode();   
    $rpkt->{ver}        = IP_VERSION_IPv4;
    $rpkt->{hlen}       = 5;
    $rpkt->{id}         = (rand() * 65535);
    $rpkt->{proto}      = IP_PROTO_UDP;
    $rpkt->{ttl}        = 255;
    $rpkt->{src_ip}     = "127.0.0.1";
    $rpkt->{dest_ip}    = "127.0.0.1";
    $rpkt->{tos}        = 0;
    $rpkt->{len}        = 0;
    $rpkt->{options}    = "";
    $rpkt->{foffset}    = 0;
    $rpkt->{flags}      = 0;
    
    my $tpkt = NetPacket::UDP->decode();
    $tpkt->{src_port}   = 0;
    $tpkt->{dest_port}  = 0;
    $tpkt->{len}        = 0;
    $tpkt->{cksum}      = 0;
    $tpkt->{data}       = "";

    $self->{'TYPE'} = 'UDP';
    $self->{'IP'}   = $rpkt;
    $self->{'UDP'}  = $tpkt;
}

sub ICMP {
    my $self = shift;
    
    my $rpkt = NetPacket::IP->decode();   
    $rpkt->{ver}        = IP_VERSION_IPv4;
    $rpkt->{hlen}       = 5;
    $rpkt->{id}         = (rand() * 65535);
    $rpkt->{proto}      = IP_PROTO_ICMP;
    $rpkt->{ttl}        = 255;
    $rpkt->{src_ip}     = "127.0.0.1";
    $rpkt->{dest_ip}    = "127.0.0.1";
    $rpkt->{tos}        = 0;
    $rpkt->{len}        = 0;
    $rpkt->{options}    = "";
    $rpkt->{foffset}    = 0;
    $rpkt->{flags}      = 0;
    
    my $tpkt = NetPacket::ICMP->decode();
    $tpkt->{type}       = ICMP_ECHO;
    $tpkt->{code}       = 0;
    $tpkt->{cksum}      = 0;
    $tpkt->{data}       = "";

    $self->{'TYPE'} = 'ICMP';
    $self->{'IP'}   = $rpkt;
    $self->{'ICMP'} = $tpkt;
}

sub Encode {
    my $self = shift;
    
    if ($self->{'TYPE'} ne 'IP') 
    {
        $self->{'IP'}->{data} = $self->{$self->{'TYPE'}}->encode($self->{'IP'});
    }
    
    return $self->{'IP'}->encode();
}

sub EncodeMultiDestIP {
    my $self = shift;
    my @dest = @_;
    my $resp;

    foreach (@dest) 
    {
        $self->ip_dest_ip($_);
        if ($self->{'TYPE'} ne 'IP') 
        {
            $self->{'IP'}->{data} = $self->{$self->{'TYPE'}}->encode($self->{'IP'});
        }
        push @{$resp->{$self->ip_dest_ip()}}, $self->{'IP'}->encode();
    }
    return $resp;
}

sub EncodeMultiSrcIP {
    my $self = shift;
    my @src = @_;
    my $resp = {};

    foreach (@src) 
    {
        $self->ip_src_ip($_);
        if ($self->{'TYPE'} ne 'IP') 
        {
            $self->{'IP'}->{data} = $self->{$self->{'TYPE'}}->encode($self->{'IP'});
        }
        push @{$resp->{$self->ip_dest_ip()}}, $self->{'IP'}->encode();
    }
    return $resp;
}

sub EncodeMegaMulti {
    my $self = shift;
    my $meta = shift;
    my $resp = {};
    
    foreach my $src_ip (@{$meta->{'src_ip'}}) {
    foreach my $dest_ip (@{$meta->{'dest_ip'}}) {
    foreach my $src_port (@{$meta->{'src_port'}}) {
    foreach my $dest_port (@{$meta->{'dest_port'}}) {

    $self->ip_src_ip($src_ip);
    $self->ip_dest_ip($dest_ip);
    
    if ($src_port == 0)  { $src_port = (rand() * 65535) }
    if ($dest_port == 0) { $dest_port = (rand() * 65535) }
     
    if ($self->{'TYPE'} eq 'TCP')
    {
        $self->tcp_src_port($src_port);
        $self->tcp_dest_port($dest_port);
    }
    
    if ($self->{'TYPE'} eq 'UDP')
    {
        $self->udp_src_port($src_port);
        $self->udp_dest_port($dest_port);
    }    
    
    if ($meta->{'random_fields'})
    {
        $self->ip_id(rand() * 65535);
        $self->ip_ttl((rand() * 200) + 40);
        
        if ($self->{'TYPE'} eq 'TCP')
        {
            $self->tcp_seqnum((rand() * 0xffff) * (rand() * 0xffff));
            $self->tcp_acknum((rand() * 0xffff) * (rand() * 0xffff));
        
        } 
    }
    
    if ($self->{'TYPE'} ne 'IP') 
    {
        $self->{'IP'}->{data} = $self->{$self->{'TYPE'}}->encode($self->{'IP'});
    }
    
    push @{$resp->{$self->ip_dest_ip()}}, $self->{'IP'}->encode();
    
    # finish the for loops
    } } } }

    return $resp;
}

#
# IP Methods
#

sub ip_id { 
    my $self = shift;
    if (@_) { $self->{'IP'}->{'id'} = shift }
    return $self->{'IP'}->{'id'};
}

sub ip_ttl { 
    my $self = shift;
    if (@_) { $self->{'IP'}->{'ttl'} = shift }
    return $self->{'IP'}->{'ttl'};
}

sub ip_proto { 
    my $self = shift;
    if (@_) { $self->{'IP'}->{'proto'} = shift }
    return $self->{'IP'}->{'proto'};
}

sub ip_src_ip { 
    my $self = shift;
    if (@_) { $self->{'IP'}->{'src_ip'} = shift }
    return $self->{'IP'}->{'src_ip'};
}

sub ip_dest_ip { 
    my $self = shift;
    if (@_) { $self->{'IP'}->{'dest_ip'} = shift }
    return $self->{'IP'}->{'dest_ip'};
}

sub ip_tos { 
    my $self = shift;
    if (@_) { $self->{'IP'}->{'tos'} = shift }
    return $self->{'IP'}->{'tos'};
}

sub ip_options { 
    my $self = shift;
    if (@_) { $self->{'IP'}->{'options'} = shift }
    return $self->{'IP'}->{'options'};
}

sub ip_flags { 
    my $self = shift;
    if (@_) { $self->{'IP'}->{'flags'} = shift }
    return $self->{'IP'}->{'flags'};
}

sub ip_data { 
    my $self = shift;
    if (@_) { $self->{'IP'}->{'data'} = shift }
    return $self->{'IP'}->{'data'};
}


#
# TCP Methods
#

sub tcp_src_port { 
    my $self = shift;
    if (@_) { $self->{'TCP'}->{'src_port'} = shift }
    return $self->{'TCP'}->{'src_port'};
}

sub tcp_dest_port { 
    my $self = shift;
    if (@_) { $self->{'TCP'}->{'dest_port'} = shift }
    return $self->{'TCP'}->{'dest_port'};
}

sub tcp_seqnum { 
    my $self = shift;
    if (@_) { $self->{'TCP'}->{'seqnum'} = shift }
    return $self->{'TCP'}->{'seqnum'};
}

sub tcp_acknum { 
    my $self = shift;
    if (@_) { $self->{'TCP'}->{'acknum'} = shift }
    return $self->{'TCP'}->{'acknum'};
}

sub tcp_flags { 
    my $self = shift;
    if (@_) { $self->{'TCP'}->{'flags'} = shift }
    return $self->{'TCP'}->{'flags'};
}

sub tcp_winsize { 
    my $self = shift;
    if (@_) { $self->{'TCP'}->{'winsize'} = shift }
    return $self->{'TCP'}->{'winsize'};
}

sub tcp_urg { 
    my $self = shift;
    if (@_) { $self->{'TCP'}->{'urg'} = shift }
    return $self->{'TCP'}->{'urg'};
}

sub tcp_options { 
    my $self = shift;
    if (@_) { $self->{'TCP'}->{'options'} = shift }
    return $self->{'TCP'}->{'options'};
}

sub tcp_data { 
    my $self = shift;
    if (@_) { $self->{'TCP'}->{'data'} = shift }
    return $self->{'TCP'}->{'data'};
}



#
# UDP Methods
#

sub udp_src_port { 
    my $self = shift;
    if (@_) { $self->{'UDP'}->{'src_port'} = shift }
    return $self->{'UDP'}->{'src_port'};
}

sub udp_dest_port { 
    my $self = shift;
    if (@_) { $self->{'UDP'}->{'dest_port'} = shift }
    return $self->{'UDP'}->{'dest_port'};
}

sub udp_len { 
    my $self = shift;
    if (@_) { $self->{'UDP'}->{'len'} = shift }
    return $self->{'UDP'}->{'len'};
}

sub udp_data { 
    my $self = shift;
    if (@_) { $self->{'UDP'}->{'data'} = shift }
    return $self->{'UDP'}->{'data'};
}


#
# ICMP Methods
#

sub icmp_type { 
    my $self = shift;
    if (@_) { $self->{'ICMP'}->{'type'} = shift }
    return $self->{'ICMP'}->{'type'};
}

sub icmp_code { 
    my $self = shift;
    if (@_) { $self->{'ICMP'}->{'code'} = shift }
    return $self->{'ICMP'}->{'code'};
}

sub icmp_data { 
    my $self = shift;
    if (@_) { $self->{'ICMP'}->{'data'} = shift }
    return $self->{'ICMP'}->{'data'};
}



1;
