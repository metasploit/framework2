
###############
##
#
#    Name: Sys.pm
#  Author: skape <mmiller [at] hick.org>
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      This module is a meterpreter extension module that provides
#      the user with the ability to interact with the networking
#      subsystem on the remote endpoint by allowing them to see the machine's
#      routine table, its IP addresses, and to even tunnel TCP connections over
#      the communication channel into the remote endpoint's network.
#
##
###############

use strict;
use IO::Socket::INET;
use Pex::Meterpreter::Arguments;
use Pex::Meterpreter::Channel;
use Pex::Meterpreter::Packet;

package Def;

#
# This is the base index for TLVs inside this extension
#
use constant NETWORK_BASE                         => 18000;
use constant TLV_TYPE_NETWORK_GENERAL_IP          => makeTlv(TLV_META_TYPE_UINT,   NETWORK_BASE +  0);
use constant TLV_TYPE_NETWORK_GENERAL_NETMASK     => makeTlv(TLV_META_TYPE_UINT,   NETWORK_BASE +  1);
use constant TLV_TYPE_NETWORK_GENERAL_GATEWAY_IP  => makeTlv(TLV_META_TYPE_UINT,   NETWORK_BASE +  2);
use constant TLV_TYPE_NETWORK_GENERAL_DNS_IP      => makeTlv(TLV_META_TYPE_UINT,   NETWORK_BASE +  3);
use constant TLV_TYPE_NETWORK_GENERAL_MAC_ADDR    => makeTlv(TLV_META_TYPE_RAW,    NETWORK_BASE +  4);
use constant TLV_TYPE_NETWORK_GENERAL_MAC_NAME    => makeTlv(TLV_META_TYPE_STRING, NETWORK_BASE +  5);
use constant TLV_TYPE_NETWORK_GENERAL_SUBNET      => makeTlv(TLV_META_TYPE_UINT,   NETWORK_BASE +  6);
use constant TLV_TYPE_NETWORK_GENERAL_REMOTE_HOST => makeTlv(TLV_META_TYPE_STRING, NETWORK_BASE + 10);
use constant TLV_TYPE_NETWORK_GENERAL_REMOTE_PORT => makeTlv(TLV_META_TYPE_UINT,   NETWORK_BASE + 11);
use constant TLV_TYPE_NETWORK_GENERAL_IFACE_GROUP => makeTlv(TLV_META_TYPE_GROUP,  NETWORK_BASE + 40);
use constant TLV_TYPE_NETWORK_GENERAL_ROUTE_GROUP => makeTlv(TLV_META_TYPE_GROUP,  NETWORK_BASE + 41);

package Pex::Meterpreter::Extension::Client::Net;

use Socket;

my $instance = undef;
my @handlers = 
(
	{
		identifier  => "Network",
		description => "Networking Commands",
		handler     => undef,
	},
	{
		identifier  => "ipconfig",
		description => "Display the endpoint's IP interface information",
		handler     => \&ipconfig,
	},
	{
		identifier  => "route",
		description => "Interact with the endpoint's routing table",
		handler     => \&route,
	},
	{
		identifier  => "portfwd",
		description => "Forward a local port to a remote host:port",
		handler     => \&portfwd,
	},
);

#
# Constructor
#
sub new
{
	my $this  = shift;
	my $class = ref($this) || $this;
	my $self  = {};
	my ($client) = @{{@_}}{qw/client/};

	# If the singleton has yet to be created...
	if (not defined($instance))
	{
		bless($self, $class);

		$self->{'client'}      = $client;
		$self->{'listeners'}   = ();
		$self->{'connections'} = ();

		$instance = $self;
	}
	else
	{
		$self = $instance;
	}
		
	$self->registerHandlers(client => $client);

	return $self;
}

sub DESTROY
{
	my $self = shift;

	$self->deregisterHandlers(client => $self->{'client'});
}

sub getClient
{
	my $self = shift;

	return $self->{'client'};
}

##
#
# Dispatch registration 
#
##

sub registerHandlers
{
	my $self = shift;
	my ($client) = @{{@_}}{qw/client/};

	foreach my $handler (@handlers)
	{
		$client->registerLocalInputHandler(
				identifier  => $handler->{'identifier'},
				description => $handler->{'description'},
				handler     => $handler->{'handler'});
	}
}

sub deregisterHandlers
{
	my $self = shift;
	my ($client) = @{{@_}}{qw/client/};

	foreach my $handler (@handlers)
	{
		$client->deregisterLocalInputHandler(
				identifier  => $handler->{'identifier'});
	}
}


##
#
# Local dispatch handlers
#
##

#
# List interfaces on the remote endpoint
#
sub ipconfigComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};
	my $res = $$packet->getResult();
	my $index = 0;
	my $iface;

	if ($res == 0)
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"ipconfig: Listing interfaces\n\n");

		# Enumerate through all of the interfaces
		while (defined($iface = $$packet->enumTlv(
				type  => Def::TLV_TYPE_NETWORK_GENERAL_IFACE_GROUP,
				index => $index++)))
		{
			my $netmask;
			my $macAddr;
			my $macName;
			my $ip;

			$ip = pack("N", $$packet->getTlv(
					type   => Def::TLV_TYPE_NETWORK_GENERAL_IP,
					buffer => $iface));
			$netmask = pack("N", $$packet->getTlv(
					type   => Def::TLV_TYPE_NETWORK_GENERAL_NETMASK,
					buffer => $iface));
			$macAddr = $$packet->getTlv(
					type   => Def::TLV_TYPE_NETWORK_GENERAL_MAC_ADDR,
					buffer => $iface);
			$macName = $$packet->getTlv(
					type   => Def::TLV_TYPE_NETWORK_GENERAL_MAC_NAME,
					buffer => $iface);

			# Print the interface's physical information
			if ((defined($macAddr)) and
			    (defined($macName)))
			{
				my $str = sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
						unpack("C*", $macAddr));

				$client->writeConsoleOutput(text => 
						"Interface: $macName\n" .
						"  phys:$str\n");
			}
			else
			{
				$client->writeConsoleOutput(text =>
						"Interface: Unknown\n");
			}

			# Print IP information
			my $str = sprintf("  inet addr:%16s  netmask: %16s\n",
					inet_ntoa($ip), Socket::inet_ntoa($netmask));

			$client->writeConsoleOutput(text =>
					$str);
		}

		$client->writeConsoleOutput(text =>
				"\n" .
				"  " . ($index - 1) . " interfaces detected.\n");
		$client->printPrompt();
	}
	else
	{
		$client->writeConsoleOutputResponse(
				cmd    => 'ipconfig',
				packet => $packet);
	}

	return 1;
}

sub ipconfig
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my $request;

	# Create the request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "network_system_ipconfig");

	$client->writeConsoleOutput(text =>
			"ipconfig: Requesting interface list...\n");
	
	# Transmit the request
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&ipconfigComplete);

	return 1;
}

#
# Get the routing table on the remote endpoint
#
sub routeComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};
	my $res = $$packet->getResult();
	my $index = 0;
	my $route;

	if ($res == 0)
	{
		$client->writeConsoleOutput(text =>
				"\n" .
				"route: Listing routes...\n\n" .
				"          Subnet          Netmask          Gateway\n" .
				" ---------------  ---------------  ---------------\n");

		while (defined($route = $$packet->enumTlv(
				type  => Def::TLV_TYPE_NETWORK_GENERAL_ROUTE_GROUP,
				index => $index++)))
		{
			my $subnet;
			my $netmask;
			my $gateway;

			$subnet = pack("N", $$packet->getTlv(
					type   => Def::TLV_TYPE_NETWORK_GENERAL_SUBNET,
					buffer => $route));
			$netmask = pack("N", $$packet->getTlv(
					type   => Def::TLV_TYPE_NETWORK_GENERAL_NETMASK,
					buffer => $route));
			$gateway = pack("N", $$packet->getTlv(
					type   => Def::TLV_TYPE_NETWORK_GENERAL_GATEWAY_IP,
					buffer => $route));

			my $str = sprintf("%16s %16s %16s\n",
					inet_ntoa($subnet), inet_ntoa($netmask), inet_ntoa($gateway));

			$client->writeConsoleOutput(text =>
					$str);
		}

		$client->writeConsoleOutput(text =>
				"\n" .
				"  " . ($index - 1) . " routes.\n");
		$client->printPrompt();
	}
	else
	{
		$client->writeConsoleOutputResponse(
				cmd    => 'ipconfig',
				packet => $packet);
	}

	return 1;
}

sub route
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my $request;

	# Create the request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "network_system_route");

	$client->writeConsoleOutput(text =>
			"ipconfig: Requesting route table...\n");
	
	# Transmit the request
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&routeComplete);

	return 1;
}

#
# Forward a local port to a remote host:port over the communication channel
#
sub portfwdComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};

	return 1;
}

sub portfwd
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv   = @{ $argumentsScalar };
	my $argc   = scalar(@argv);
	my $parser = Pex::Meterpreter::Arguments->new(
			argv => $argumentsScalar, 
			fmt  => 'arvL:l:h:p:P');
	my $banner = 1;
	my $localHost;
	my $localPort;
	my $remoteHost;
	my $remotePort;
	my $command;
	my $proxy = 0;
	my $toggle;

	# No arguments?
	goto out if ($argc == 1);

	# Parse the argument list
	while (defined($toggle = $parser->parse()))
	{
		if ($toggle eq 'a')
		{
			$command = "network_portfwd_add";
		}
		elsif ($toggle eq 'r')
		{
			$command = "network_portfwd_remove";
		}
		elsif ($toggle eq 'v')
		{
			$command = "network_portfwd_view";
		}
		elsif ($toggle eq 'L')
		{
			$localHost = $parser->getArgument();
		}
		elsif ($toggle eq 'l')
		{
			$localPort = $parser->getArgument();
		}
		elsif ($toggle eq 'h')
		{
			$remoteHost = $parser->getArgument();
		}
		elsif ($toggle eq 'p')
		{
			$remotePort = $parser->getArgument();
		}
		elsif ($toggle eq 'P')
		{
			$proxy = 1;
		}
	}

	# Check to make sure that a command was supplied
	if (not defined($command))
	{
		$client->writeConsoleOutput(text =>
				"Error: No command was supplied.\n");
		goto out;
	}

	$banner = 0;

	# Do what the command instructs
	if ($command eq "network_portfwd_add")
	{
		if ((not defined($localPort)) or
		    (not defined($remoteHost)) or
		    (not defined($remotePort)))
		{
			$client->writeConsoleOutput(text =>
					"Error: Missing one or more of local port/remote host/remote port.\n");
			goto out;
		}


		# Create the local listener
		if (not defined($instance->createListener(
				localHost  => $localHost,
				localPort  => $localPort,
				remoteHost => $remoteHost,
				remotePort => $remotePort)))
		{
			$client->writeConsoleOutput(text =>
					"Error: Failed to create listener on local port $localPort.\n");
			goto out;
		}

		$client->writeConsoleOutput(text =>
				"portfwd: Successfully created local listener on port $localPort.\n");
	}
	elsif ($command eq "network_portfwd_remove")
	{
		# Destroy the local listener
		if (not defined($instance->destroyListener(
				localHost => $localHost,
				localPort => $localPort)))
		{
			$client->writeConsoleOutput(text =>
					"Error: Failed to destroy listener on local port $localPort.\n");
			goto out;
		}

		$client->writeConsoleOutput(text =>
				"portfwd: Successfully destroyed local listener on port $localPort.\n");
	}
	elsif ($command eq "network_portfwd_view")
	{
		$instance->printListeners();
	}

out:
	if ($banner)
	{
		$client->writeConsoleOutput(text =>
				"Usage: portfwd [ -arv ] [ -L laddr ] [ -l lport ] [ -h rhost ] [ -p rport ]\n" .
				"               [ -P ]\n" .
				"\n" .
				"  -a      Add a port forward\n" .
				"  -r      Remove a port forward\n" .
				"  -v      View port forward list\n" .
				"  -L      The local address to listen on\n" .
				"  -l      The local port to listen on\n" .
				"  -h      The remote host to connect to\n" .
				"  -p      The remote port to connect to\n" .
				"  -P      Create a local proxy listener that builds a dynamic port forward.\n");

	}

	return 1;
}

##
#
# Port Forwarding
#
##

#
# Create a new local port forward listener
#
sub createListener
{
	my $self = shift;
	my ($localHost, $localPort, $remoteHost, $remotePort) = @{{@_}}{qw/localHost localPort remoteHost remotePort/};
	my $client = $self->getClient();
	my $listener = {};

	$localHost = "0.0.0.0" if (not defined($localHost));

	# Initialize the listener context
	$listener->{'localHost'}  = $localHost;
	$listener->{'localPort'}  = $localPort;
	$listener->{'remoteHost'} = $remoteHost;
	$listener->{'remotePort'} = $remotePort;
	$listener->{'socket'}     = IO::Socket::INET->new(
			LocalHost => $localHost,
			LocalPort => $localPort,
			Listen    => 5,
			ReuseAddr => 1,
			Proto     => "tcp");

	# Could we bind to the local port?
	if (not defined($listener->{'socket'}))
	{
		return undef;
	}

	# Push the listener into the list
	push @{ $self->{'listeners'} }, $listener;

	# Add the socket as a selectable
	$client->addSelectable(
			handle                 => $listener->{'socket'},
			notifyHandler          => \&notifyListener,
			notifyHandlerParameter => $listener);

	return $listener;
}

#
# Destroy a given local port forward listener
#
sub destroyListener
{
	my $self = shift;
	my ($localHost, $localPort) = @{{@_}}{qw/localHost localPort/};
	my $client = $self->getClient();
	my $idx = 0;
	my $res;

	foreach my $current (@{ $self->{'listeners'} })
	{
		if ($current->{'localPort'} == $localPort)
		{
			# Remove the listener from the list of listeners
			splice @{ $self->{'listeners'} }, $idx, 1;	

			# Remove the listener from the selectables
			$client->removeSelectable(
					handle => $current->{'socket'});

			# Close the listening socket
			close($current->{'socket'});

			$res = 1;

			last;
		}

		$idx++;
	}

	return $res;
}

#
# Display all of the local listeners to the console
#
sub printListeners
{
	my $self = shift;
	my $client = $self->getClient();

	$client->writeConsoleOutput(text =>
			"Local port forward listeners:\n\n");

	foreach my $listener (@{ $self->{'listeners'} })
	{
		$client->writeConsoleOutput(text =>
				"  " . $listener->{'localHost'} . ":" . $listener->{'localPort'} . 
				" <-> " . $listener->{'remoteHost'} . ":" . $listener->{'remotePort'} . "\n");
	}
}

#
# Notification routine that is called when a new connection arrives on the local
# listener
#
sub notifyListener
{
	my ($client, $listener) = @{{@_}}{qw/client context/};
	my $connectionContext = {};

	# Accept the incoming client connection
	$connectionContext->{'socket'} = $listener->{'socket'}->accept;

	# Open the TCP channel with the remote endpoint
	openTcpChannel(
			client                     => $client,
			remoteHost                 => $listener->{'remoteHost'},
			remotePort                 => $listener->{'remotePort'},
			completionHandler          => \&openTcpChannelPortForwardComplete,
			completionHandlerParameter => $connectionContext);

	return 1;
}

#
# Notification routine that is called when a connection has data or has been
# closed
#
sub notifyConnection
{
	my ($client, $connection) = @{{@_}}{qw/client context/};
	my $channel = $connection->{'channel'};
	my $buf;
	my $res;

	$res = sysread($connection->{'socket'}, $buf, 8192, 0);

	# If the read fails for some reason
	if ((not defined($res)) or 
	    ($res <= 0))
	{
		# If the connection has an associated channel, close it
		if (defined($channel))
		{
			$$channel->close(
					client => $client);
		}

		# Remove the connection from the selectable list
		$client->removeSelectable(
				handle => $connection->{'socket'});

		# Close the connection
		close($client->{'socket'});

		goto out;
	}
	elsif (defined($channel))
	{
		# Write the data read in from the wire to the remote endpoint
		$$channel->write(
				client => $client,
				buffer => $buf);
	}

out:
	return 1;
}

#
# Completion handler for allocation a TCP channel for a port forward
#
sub openTcpChannelPortForwardComplete
{
	my ($client, $console, $packet, $connection) = @{{@_}}{qw/client console parameter handlerParameter/};
	my $res = $$packet->getResult();

	if ($res == 0)
	{
		my $channelId = $$packet->getTlv(type => Def::TLV_TYPE_CHANNEL_ID);
		my $channel;

		# If a channel was supplied, allocate a local instance of it
		if ((defined($channelId)) and
		    (defined($channel = Pex::Meterpreter::Channel->new(id => $channelId))))
		{
			$channel->setType(type => "network_tcp");

			# Set the local I/O handler for this channel
			$channel->setLocalIoHandler(
					handler => \&portForwardConnectionDio,
					context => $connection);

			# Keep a reference to the channel
			$connection->{'channel'} = \$channel;
		}

		# Insert the connection into the selectable list
		$client->addSelectable(
				handle                 => $connection->{'socket'},
				notifyHandler          => \&notifyConnection,
				notifyHandlerParameter => $connection);
	}
	else
	{
		$client->writeConsoleOutputResponse(
				cmd    => 'open_tcp_channel',
				packet => $packet);
	}

	return 1;
}

#
# Local channel I/O handler for the port forward client connection
#
sub portForwardConnectionDio
{
	my ($channel, $connection, $mode, $buffer, $length) = @{{@_}}{qw/channel context mode buffer length/};
	my $res = 1;

	if ($mode == Def::CHANNEL_DIO_MODE_WRITE)
	{
		# Write the data to the wire
		syswrite($connection->{'socket'}, $buffer, $length, 0);

		$res = $length;
	}
	elsif ($mode == Def::CHANNEL_DIO_MODE_CLOSE)
	{
		my $client = $instance->getClient();

		# Remove the connection from the selectable list
		$client->removeSelectable(
				handle => $connection->{'socket'});

		# Close the connection
		close($client->{'socket'});
	}

	return $res;
}

##
#
# Generic network socket channel allocations
#
##

sub openTcpChannel
{
	my ($client, $remoteHost, $remotePort, $completionHandler, $completionHandlerParameter) = @{{@_}}{qw/client remoteHost remotePort completionHandler completionHandlerParameter/};
	my $request;

	# Create the request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "network_open_tcp_channel");
	
	# Add the remote host information
	$request->addTlv(
			type  => Def::TLV_TYPE_NETWORK_GENERAL_REMOTE_HOST,
			value => $remoteHost);
	$request->addTlv(
			type  => Def::TLV_TYPE_NETWORK_GENERAL_REMOTE_PORT,
			value => $remotePort);

	# Transmit the request
	$client->transmitPacket(
			packet                     => \$request,
			completionHandler          => $completionHandler,
			completionHandlerParameter => $completionHandlerParameter);

	return 1;
}

1;
