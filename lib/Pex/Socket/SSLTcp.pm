#!/usr/bin/perl
###############

##
#         Name: Socket.pm
#       Author: spoonm <ninjatools [at] hush.com>
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::Socket::SSLTcp;
use strict;
use base 'Pex::Socket::Tcp';

sub new {
  my $class = shift;
  my $self = bless({ }, $class);

  my $hash = shift;
  return($self);
}

sub Close {
  my $self = shift;
  Net::SSLeay::Free($self->{'SSLFd'});
  Net::SSLeay::CTX_free($self->{'SSLCtx'});
  $self->SUPER::Close;
}

sub _MakeSocket {
  my $self = shift;
  return if(!$self->SUPER::_MakeSocket);

  my $sock = $self->Socket;

  # Create SSL Context
  $self->{'SSLCtx'} = Net::SSLeay::CTX_new();
  # Configure session for maximum interoperability
  Net::SSLeay::CTX_set_options($self->{'SSLCtx'}, &Net::SSLeay::OP_ALL);
  # Create the SSL file descriptor
  $self->{'SSLFd'}  = Net::SSLeay::new($self->{'SSLCtx'});
  # Bind the SSL descriptor to the socket
  Net::SSLeay::set_fd($self->{'SSLFd'}, $sock->fileno);        
  # Negotiate connection
  my $sslConn = Net::SSLeay::connect($self->{'SSLFd'});

  if($sslConn <= 0) {
    $self->SetError('Error setting up ssl: ' . Net::SSLeay::print_errs());
    $self->close;
    return;
  }

  return($sock->fileno);
}


# This should be called when we know the socket has data waiting for us.
# We try to ssl read, if there is data return, we return with it, otherwise
# we loop for several tries waiting for ssl data
sub _RecvSSL {
  my $self = shift;
  my $sslEmptyRead = @_ ? shift : 5;

  while(1) {
    my $data = Net::SSLeay::read($self->{'SSLFd'});
    if(!length($data)) {
      if(!--$sslEmptyRead) {
        return;
      }
      select(undef, undef, undef, .1);
    }
    else {
      return($data);
    }
  }
}

1;
