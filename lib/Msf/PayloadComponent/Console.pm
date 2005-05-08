

package Msf::PayloadComponent::Console;
use strict;
use IO::Handle;
use IO::Select;
use base 'Msf::Payload';
use vars qw{ @ISA };

sub _Import {
  my $class = shift;
  @ISA = ('Msf::Payload');
  foreach (@_) {
    eval("use $_");
    unshift(@ISA, $_);
  }
}

sub LoadConsole {
  my $self = shift;
  my $console = $self->GetVar('_Console');
  $console = 'Msf::PayloadComponent::TextConsole' if(!$console);
  __PACKAGE__->_Import($console);
  $self->SUPER::LoadConsole;
}

sub HandleConsole {
  my $self = shift;
  $self->LoadConsole;
  $self->_HandleConsole;
}

# Pipe(Local|Remote)(In|Out) methods:
#	1. All pipes must support sysread/syswrite
#	2. The "Src" functions routine logging info for the pipe
#	3. Overload these or set via $self->{ }


# Pipe connected to the console input
sub PipeLocalIn {
	my $self = shift;
	
	if (@_) {
		$self->{'PipeLocalIn'} = shift();
		delete($self->{'PipeLocalSrc'});
	}

	if (! exists($self->{'PipeLocalIn'})) {
		$self->{'PipeLocalIn'} = IO::Handle->new_from_fd(0, '<');
		$self->PipeLocalName('stdio');
	} 
	
	return $self->{'PipeLocalIn'};
}


# Pipe connected to the console output
sub PipeLocalOut {
	my $self = shift;
	
	if (@_) {
		$self->{'PipeLocalOut'} = shift();
		delete($self->{'PipeLocalSrc'});
	}
		
	if (! exists($self->{'PipeLocalOut'})) {
		$self->{'PipeLocalOut'} = IO::Handle->new_from_fd(1, '>');	
	} 
	
	return $self->{'PipeLocalOut'};
}


# This should be set to an identifier such as 'stdin' or 'console'
# unless it has been overloaded to return a socket, in which case
# it should return the IP address of the socket peer.
sub PipeLocalName {
	my $self = shift;

	$self->{'PipeLocalName'} = shift() if @_;
	if (! exists($self->{'PipeLocalName'})) {
		$self->{'PipeLocalName'} = 'console';
	}
	return $self->{'PipeLocalName'};	
}


# This information is used in the logging routines to identify the
# true source of the console input. If it has not been overloaded
# by a subclass, it will configure itself based on the contents of
# the local input and output pipes.
sub PipeLocalSrc {
	my $self = shift;

	$self->{'PipeLocalSrc'} = shift() if @_;

	if (! exists($self->{'PipeLocalSrc'})) {
	
		my $info = $self->PipeInfo($self->PipeLocalIn, 'LocalIn');
		
		if ($self->PipeLocalIn ne $self->PipeLocalOut) {
			$info .= " ". $self->PipeInfo($self->PipeLocalOut, 'LocalOut');
		}
		
		$self->{'PipeLocalSrc'} = $info;
	}
	return $self->{'PipeLocalSrc'};
}


# Pipe connected to the command input of the remote service
sub PipeRemoteIn {
	my $self = shift;

	if (@_) {
		$self->{'PipeRemoteIn'} = shift();
		delete($self->{'PipeRemoteSrc'});
	}
		
	if (! exists($self->{'PipeRemoteIn'})) {
		$self->{'PipeRemoteIn'} = IO::Handle->new_from_fd(0, '<');	
	}
	
	# Set the PipeRemoteName to the IP address of the socket
	if (ref($self->{'PipeRemoteIn'}) =~ /IO::Socket/) {
		my $name;
		eval { $name = $self->{'PipeRemoteIn'}->peerhost };
		$self->PipeRemoteName($name);
	}
	
	return $self->{'PipeRemoteIn'};
}


# Pipe connected to the command output of the remote service
sub PipeRemoteOut {
	my $self = shift;

	if (@_) {
		$self->{'PipeRemoteOut'} = shift();
		delete($self->{'PipeRemoteSrc'});
	}
		
	if (! exists($self->{'PipeRemoteOut'})) {
		$self->{'PipeRemoteOut'} = IO::Handle->new_from_fd(1, '>');	
	} 
	
	# Set the PipeRemoteName to the IP address of the socket
	if (ref($self->{'PipeRemoteOut'}) =~ /IO::Socket/) {
		my $name;
		eval { $name = $self->{'PipeRemoteOut'}->peerhost };
		$self->PipeRemoteName($name);
	}
	
	return $self->{'PipeRemoteOut'};
}


# This should return the IP address of the remote end, or another
# identifier if applicable. This method is set when the first call
# to PipeRemote(In|Out) is made.
sub PipeRemoteName {
	my $self = shift;

	$self->{'PipeRemoteName'} = shift() if @_;
	if (! defined($self->{'PipeRemoteName'})) {
		$self->{'PipeRemoteName'} = 'remote';
	}
	return $self->{'PipeRemoteName'};
}


# This information is used in the logging routines to identify the
# true source of the remote service. If it has not been overloaded
# by a subclass, it will configure itself based on the contents of
# the remote input and output pipes.
sub PipeRemoteSrc {
	my $self = shift;

	$self->{'PipeRemoteSrc'} = shift() if @_;

	if (! exists($self->{'PipeRemoteSrc'})) {
	
		my $info = $self->PipeInfo($self->PipeRemoteIn, 'RemoteIn');
		
		if ($self->PipeRemoteIn ne $self->PipeRemoteOut) {
			$info .= " ". $self->PipeInfo($self->PipeRemoteOut, 'RemoteOut');
		}
		
		$self->{'PipeRemoteSrc'} = $info;
	}
		
	return $self->{'PipeRemoteSrc'};
}


# PipeRead/PipeWrite can handle:
#	1. IO::Handle
#	2. IO::Socket
#
# Returns
#	undef on success (non-error)
#	-1 on error
#

sub PipeRead {
	my $self = shift;
	my $pipe = @_ ? shift() : return;
	my $type = ref($pipe);
	my $data;
	
	if ($type =~ /IO::Socket/) {
		eval { $pipe->recv($data, 4096) };
		if (length($data) == 0) {
			return;
		}
	}
	else {
		$pipe->sysread($data, 4096);
		if (length($data) == 0) {
			return;
		}
	}

	return $data;
}


sub PipeWrite {
	my $self = shift;
	my $pipe = @_ ? shift() : return;
	my $data = @_ ? shift() : return '';
	my $type = ref($pipe);
	my $ret;
	
	if ($type  =~ /IO::Socket/) {
		my $ecnt = 0;
		while ( length($data) ) {
			eval { $ret = $pipe->send($data) };

			# Handle system errors
			if ($ret <= 0 || $@) {
				return;
			}
			
			# Maximum of two seconds
			return if $ecnt > 8;
			
			# How much is left to send?
			$data = substr($data, $ret);

			# Handle partial sends
			if (length($data) && ++$ecnt) {
				select(undef, undef, undef, 0.25);
				next;
			}
		}
	}
	else {
		my $block = $pipe->blocking;
		$pipe->blocking(1);
		$ret = $pipe->printflush($data);
		$pipe->blocking($block);
		return if $ret <= 0;
	}
	
	return $ret;
}


# Creates a textual representation of a given Pipe
sub PipeInfo {
	my $self 	= shift;
	my $pipe 	= @_ ? shift() : return;
	my $dflt	= @_ ? shift() : "$pipe";
	my $pType	= ref($pipe);
	my $pInfo;
	
	if ($pType =~ /IO::Socket/) {
		eval {
			$pInfo = $pipe->sockhost.":".$pipe->sockport.
			         " <-> ".
					 $pipe->peerhost.":".$pipe->peerport;
		};
	}
	elsif ($pType =~  /IO::Handle/) {
		$pInfo = "$dflt:fd".$pipe->fileno();
	}
	else {
		$pInfo = "$dflt:$pipe";
	}
	
	return $pInfo;
}

sub PipeClose {
	my $self	= shift;
	my $pipe 	= @_ ? shift() : return;
	my $pType	= ref($pipe);
	
	if ($pType =~ /IO::Socket/) {
		eval { $pipe->shutdown(2) };
	}
	
	eval { $pipe->close };
	return;
}

1;
