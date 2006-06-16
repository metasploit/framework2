
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

  # Can segfault if you double free this :<
  if (! exists($self->{'SSL_Already_Freed'})) {
    Net::SSLeay::free($self->SSLFd);
    Net::SSLeay::CTX_free($self->SSLCtx);
    $self->{'SSL_Already_Freed'}++;
  } 

  $self->SUPER::Close;
}

sub _MakeSocket {
  my $self = shift;
  return if(!$self->SUPER::_MakeSocket);

  my $sock = $self->Socket;
  
  delete($self->{'SSL_Already_Freed'});

  # Create SSL Context
  $self->SSLCtx(Net::SSLeay::CTX_new());
  
  # Configure session for maximum interoperability
  Net::SSLeay::CTX_set_options($self->SSLCtx, &Net::SSLeay::OP_ALL);
  
  # Create the SSL file descriptor
  $self->SSLFd(Net::SSLeay::new($self->SSLCtx));
  
  # Bind the SSL descriptor to the socket
  Net::SSLeay::set_fd($self->SSLFd, $sock->fileno);        
  
  # Set IO to be non-blocking 
  $sock->blocking(0);
  
  # Negotiate the SSL connection (ideas taken from IO::Socket::SSL)
  while (Net::SSLeay::connect($self->SSLFd) < 1) {
    my $sslError = Net::SSLeay::get_error($self->SSLFd, -1);
    my $sslRE    = Net::SSLeay::ERROR_WANT_READ();
    my $sslWE    = Net::SSLeay::ERROR_WANT_WRITE();
    
	if ($sslError == $sslRE || $sslError == $sslWE) {
	    require IO::Select;
	    my $sel = new IO::Select($sock);
	    next if (($sslError == $sslWE) ? 
            $sel->can_write($self->Timeout): $sel->can_read($self->Timeout));
	}
    $self->SetError('Error setting up ssl: ' . Net::SSLeay::print_errs());
    $sock->close;
    return;
  }

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
