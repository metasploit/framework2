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

my $SSL_SUPPORT;

# Determine if SSL support is enabled
BEGIN
{
    if (eval "require Net::SSLeay")
    {
        Net::SSLeay->import();
        Net::SSLeay::load_error_strings();
        Net::SSLeay::SSLeay_add_ssl_algorithms();
        Net::SSLeay::randomize();
        $SSL_SUPPORT++;
    }
}


sub new {
  my $class = shift;
  my $self = bless({ }, $class);
  return if(!$SSL_SUPPORT);
  my $hash = { @_ };
  $self->SetOptions($hash);
  $self->Init;

  $self->_MakeSocket;
#  return if(!$self->_MakeSocket);
  return($self);
}

sub SSLFd {
  my $self = shift;
  $self->{'SSLFd'} = shift if(@_);
  return($self->{'SSLFd'});
}
sub SSLCtx {
  my $self = shift;
  $self->{'SSLCtx'} = shift if(@_);
  return($self->{'SSLCtx'});
}

sub Close {
  my $self = shift;
  Net::SSLeay::free($self->SSLFd);
  Net::SSLeay::CTX_free($self->SSLCtx);
  $self->SUPER::Close;
}

sub _MakeSocket {
  my $self = shift;
  return if(!$self->SUPER::_MakeSocket);

  my $sock = $self->Socket;

  $sock->blocking(1);

  # Create SSL Context
  $self->SSLCtx(Net::SSLeay::CTX_new());
  # Configure session for maximum interoperability
  Net::SSLeay::CTX_set_options($self->SSLCtx, &Net::SSLeay::OP_ALL);
  # Create the SSL file descriptor
  $self->SSLFd(Net::SSLeay::new($self->SSLCtx));
  # Bind the SSL descriptor to the socket
  Net::SSLeay::set_fd($self->SSLFd, $sock->fileno);        
  # Negotiate connection
  my $sslConn = Net::SSLeay::connect($self->SSLFd);

  if($sslConn <= 0) {
    $self->SetError('Error setting up ssl: ' . Net::SSLeay::print_errs());
    $sock->close;
    return;
  }

  $sock->blocking(0);

  return($sock);
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
        $self->SetError(Net::SSLeay::print_errs());
        return;
      }
      select(undef, undef, undef, .1);
    }
    else {
      return($data);
    }
  }
}

sub _DoSend {
  my $self = shift;
  my $data = shift;
  return(Net::SSLeay::ssl_write_all($self->{'SSLFd'}, $data));
}

sub _DoRecv {
  my $self = shift;
  my $length = shift;
  my $trys = shift;
  return($self->_RecvSSL($trys));
}

sub _UnitTest {
  my $class = shift;
  print STDOUT "Connecting to ssl google.com:443\n";
  my $sock = $class->new('PeerAddr' => 'google.com', 'PeerPort', 443);
  if(!$sock || $sock->IsError) {
    print STDOUT "Error creating socket: $!\n";
    return;
  }
  $class->_UnitTestGoogle($sock);
}

1;
