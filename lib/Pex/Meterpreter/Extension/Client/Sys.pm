
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
#      the user with the ability to get information about the system and to
#      interact with the registry if the remote endpoint supports it.
#
##
###############

use strict;
use Pex::Meterpreter::Packet;

package Def;

use constant SYS_BASE                     => 15000;
use constant TLV_TYPE_USER_NAME           => makeTlv(TLV_META_TYPE_STRING, SYS_BASE +  0);
use constant TLV_TYPE_COMPUTER_NAME       => makeTlv(TLV_META_TYPE_STRING, SYS_BASE + 10);
use constant TLV_TYPE_OS_NAME             => makeTlv(TLV_META_TYPE_STRING, SYS_BASE + 11);
use constant TLV_TYPE_REGISTRY_KEY_PATH   => makeTlv(TLV_META_TYPE_STRING, SYS_BASE + 50);
use constant TLV_TYPE_REGISTRY_KEY_NAME   => makeTlv(TLV_META_TYPE_STRING, SYS_BASE + 51);
use constant TLV_TYPE_REGISTRY_KEYS       => makeTlv(TLV_META_TYPE_GROUP,  SYS_BASE + 52);
use constant TLV_TYPE_REGISTRY_VALUE_NAME => makeTlv(TLV_META_TYPE_STRING, SYS_BASE + 53);
use constant TLV_TYPE_REGISTRY_VALUE_TYPE => makeTlv(TLV_META_TYPE_STRING, SYS_BASE + 54);
use constant TLV_TYPE_REGISTRY_VALUE_DATA => makeTlv(TLV_META_TYPE_STRING, SYS_BASE + 55);
use constant TLV_TYPE_REGISTRY_VALUE      => makeTlv(TLV_META_TYPE_GROUP,  SYS_BASE + 56);
use constant TLV_TYPE_REGISTRY_VALUES     => makeTlv(TLV_META_TYPE_GROUP,  SYS_BASE + 57);

package Pex::Meterpreter::Extension::Client::Sys;

my $instance = undef;
my @handlers = 
(
	{
		identifier  => "System",
		description => "Remote system information",
		handler     => undef,
	},
	{
		identifier  => "getuid",
		description => "Get the remote user indentifier.",
		handler     => \&getuid,
	},
	{
		identifier  => "sysinfo",
		description => "Get system information such as OS version.",
		handler     => \&sysinfo,
	},
	{
		identifier  => "rev2self",
		description => "Revert to self, possibly escalating privileges.",
		handler     => \&rev2self,
	},

# These commands were implemented in the server half of the extension but the
# code was lost during hardware failure.  Will eventually re-code.
#
#	{
#		identifier  => "Registry",
#		description => "Registry",
#		handler     => undef,
#	},
#	{
#		identifier  => "reg_createkey",
#		description => "Creates a registry key.",
#		handler     => \&regCreateKey,
#	},
#	{
#		identifier  => "reg_deletekey",
#		description => "Deletes a registry key.",
#		handler     => \&regDeleteKey,
#	},
#	{
#		identifier  => "reg_setvalue",
#		description => "Sets a registry value.",
#		handler     => \&regSetValue,
#	},
#	{
#		identifier  => "reg_getvalue",
#		description => "Gets a registry value.",
#		handler     => \&regGetValue,
#	},
#	{
#		identifier  => "reg_enumkey",
#		description => "Enumerates registry keys at a given key.",
#		handler     => \&regEnumKey,
#	},
#	{
#		identifier  => "reg_enumvalue",
#		description => "Enumerates registry values at a given key.",
#		handler     => \&regEnumValue,
#	},
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

		$self->{'client'} = $client;

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
# Get the remote user's identifier
#
sub getuidComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};
	my $res = $$packet->getResult();

	if ($res == 0)
	{
		my $username = $$packet->getTlv(
				type => Def::TLV_TYPE_USER_NAME);

		$client->writeConsoleOutput(text => 
				"\n");

		if (defined($username))
		{
			$client->writeConsoleOutput(text => 
					"Username: $username\n");
		}

		$client->printPrompt();
	}
	else
	{
		$client->writeConsoleOutputResponse(
				cmd    => 'getuid',
				packet => $packet);
	}

	return 1;
}

sub getuid
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my $request;

	# Create the sys_getuid request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "sys_getuid");

	# Transmit
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&getuidComplete);

	return 1;
}

#
# Gets information about the remote endpoint, such as OS version
#
sub sysinfoComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};
	my $res = $$packet->getResult();

	if ($res == 0)
	{
		my $computer = $$packet->getTlv(
				type => Def::TLV_TYPE_COMPUTER_NAME);
		my $os = $$packet->getTlv(
				type => Def::TLV_TYPE_OS_NAME);

		$client->writeConsoleOutput(text => 
				"\n");

		if (defined($computer))
		{
			$client->writeConsoleOutput(text => 
					"Computer: $computer\n");
		}
		
		if (defined($os))
		{
			$client->writeConsoleOutput(text => 
					"Computer: $os\n");
		}

		$client->printPrompt();
	}
	else
	{
		$client->writeConsoleOutputResponse(
				cmd    => 'sysinfo',
				packet => $packet);
	}

	return 1;
}

sub sysinfo
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my $request;

	# Create the sys_sysinfo request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "sys_sysinfo");
	
	# Transmit 
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&sysinfoComplete);

	return 1;
}

#
# Instructs the remote endpoint to call RevertToSelf
#
sub rev2selfComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};

	$client->writeConsoleOutputResponse(
			cmd    => 'rev2self',
			packet => $packet);

	return 1;
}

sub rev2self
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my $request;

	# Create the sys_rev2self request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "sys_rev2self");
	
	# Transmit the request
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&rev2selfComplete);

	return 1;
}

#
# Creates a registry key on the remote endpoint
#
sub regCreateKeyComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};

	$client->writeConsoleOutputResponse(
			cmd    => 'reg_createkey',
			packet => $packet);

	return 1;
}

sub regCreateKey
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $request;

	if ($argc == 1)
	{
		$client->writeConsoleOutput(text =>
				"Usage: reg_createkey [key path]\n");
		goto out;
	}

	# Create the sys_reg_createkey request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "sys_reg_createkey");
	
	$request->addTlv(
			type  => Def::TLV_TYPE_REGISTRY_KEY_PATH,
			value => $argv[1]);


	# Transmit the request
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&regCreateKeyComplete);

out:
	return 1;
}

#
# Deletes a registry key on the remote endpoint
#
sub regDeleteKeyComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};

	$client->writeConsoleOutputResponse(
			cmd    => 'reg_deletekey',
			packet => $packet);

	return 1;
}


sub regDeleteKey
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $request;

	if ($argc == 1)
	{
		$client->writeConsoleOutput(text =>
				"Usage: reg_deletekey [key path]\n");
		goto out;
	}

	# Create the sys_reg_deletekey request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "sys_reg_deletekey");
	
	$request->addTlv(
			type  => Def::TLV_TYPE_REGISTRY_KEY_PATH,
			value => $argv[1]);


	# Transmit the request
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&regDeleteKeyComplete);

out:

	return 1;
}

#
# Sets a registry value on the remote endpoint
#
sub regSetValueComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};

	$client->writeConsoleOutputResponse(
			cmd    => 'reg_setvalue',
			packet => $packet);

	return 1;
}

sub regSetValue
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $request;

	if ($argc < 5)
	{
		$client->writeConsoleOutput(text =>
				"Usage: reg_setvalue [key path] [value name] [value type] [value data]\n" .
				"   Ex: regsetvalue HKEY_LOCAL_MACHINE\\Dog Smith REG_SZ \"what up\"\n");
		goto out;
	}

	# Create the sys_reg_setvalue request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "sys_reg_setvalue");
	
	# Add TLVs
	$request->addTlv(
			type  => Def::TLV_TYPE_REGISTRY_KEY_PATH,
			value => $argv[1]);
	$request->addTlv(
			type  => Def::TLV_TYPE_REGISTRY_VALUE_NAME,
			value => $argv[2]);
	$request->addTlv(
			type  => Def::TLV_TYPE_REGISTRY_VALUE_TYPE,
			value => $argv[3]);
	$request->addTlv(
			type  => Def::TLV_TYPE_REGISTRY_VALUE_DATA,
			value => $argv[4]);

	# Transmit
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&regSetValueComplete);

out:
	return 1;
}

#
# Get a registry value's data
#
sub regGetValueComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};
	my $res = $$packet->getResult();

	if ($res == 0)
	{
		my $key;
		my $value;
		my $type;
		my $data;

		$key = $$packet->getTlv(
				type => Def::TLV_TYPE_REGISTRY_KEY_PATH);
		$value = $$packet->getTlv(
				type => Def::TLV_TYPE_REGISTRY_VALUE_NAME);
		$type = $$packet->getTlv(
				type => Def::TLV_TYPE_REGISTRY_VALUE_TYPE);
		$data = $$packet->getTlv(
				type => Def::TLV_TYPE_REGISTRY_VALUE_DATA);

		$client->writeConsoleOutput(text =>
				"\n" .
				"Registry value information:\n" .
				"  Key  : $key\n" .
				"  Value: $value\n" .
				"  Type : $type\n" .
				"  Data : $data\n");

		$client->printPrompt();
	}
	else
	{
		$client->writeConsoleOutputResponse(
				cmd    => 'reg_getvalue',
				packet => $packet);
	}

	return 1;
}

sub regGetValue
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $request;

	if ($argc < 3)
	{
		$client->writeConsoleOutput(text =>
				"Usage: reg_getvalue [key path] [value name]\n" .
				"   Ex: reg_getvalue HKEY_LOCAL_MACHINE\\Dog Smith\n");
		goto out;
	}

	# Create the sys_reg_getvalue request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "sys_reg_getvalue");
	
	# Add TLVs
	$request->addTlv(
			type  => Def::TLV_TYPE_REGISTRY_KEY_PATH,
			value => $argv[1]);
	$request->addTlv(
			type  => Def::TLV_TYPE_REGISTRY_VALUE_NAME,
			value => $argv[2]);

	# Transmit
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&regGetValueComplete);

out:
	return 1;
}

#
# Enumerates all of the sub keys of a given key
#
sub regEnumKeyComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};
	my $res = $$packet->getResult();

	if ($res == 0)
	{
		my $idx = 0;
		my $name;
		my $key;

		$key = $$packet->getTlv(
				type => Def::TLV_TYPE_REGISTRY_KEY_PATH);

		$client->writeConsoleOutput(text =>
				"\n" .
				"Enumeration of keys in '$key':\n");

		# Enumerate all of the sub keys in the response
		while (defined($name = $$packet->enumTlv(
				type  => Def::TLV_TYPE_REGISTRY_KEY_NAME,
				index => $idx++)))
		{
			$client->writeConsoleOutput(text => 
					"  $name\n");
		}

		$client->writeConsoleOutput(text =>
				"\n" .
				"  $idx total sub keys.\n");

		$client->printPrompt();
	}
	else
	{
		$client->writeConsoleOutputResponse(
				cmd    => 'reg_enumkey',
				packet => $packet);
	}

	return 1;
}

sub regEnumKey
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $request;

	if ($argc == 1)
	{
		$client->writeConsoleOutput(text =>
				"Usage: reg_enumkey [key path]\n");
		goto out;
	}

	# Create the sys_reg_enumkey request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "sys_reg_enumkey");
	
	# Add TLV
	$request->addTlv(
			type  => Def::TLV_TYPE_REGISTRY_KEY_PATH,
			value => $argv[1]);

	# Transmit
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&regEnumKeyComplete);

out:
	return 1;
}

#
# Enumerates registry values in the context of a given key
#
sub regEnumValueComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};
	my $res = $$packet->getResult();

	if ($res == 0)
	{
		my $idx = 0;
		my $name;
		my $key;

		$key = $$packet->getTlv(
				type => Def::TLV_TYPE_REGISTRY_KEY_PATH);

		$client->writeConsoleOutput(text =>
				"\n" .
				"Enumeration of values in '$key':\n");

		# Enumerate all of the values in the response
		while (defined($name = $$packet->enumTlv(
				type  => Def::TLV_TYPE_REGISTRY_VALUE_NAME,
				index => $idx++)))
		{
			$client->writeConsoleOutput(text => 
					"  $name\n");
		}

		$client->writeConsoleOutput(text =>
				"\n" .
				"  $idx total values.\n");

		$client->printPrompt();
	}
	else
	{
		$client->writeConsoleOutputResponse(
				cmd    => 'reg_enumvalue',
				packet => $packet);
	}

	return 1;
}

sub regEnumValue
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my @argv = @{ $argumentsScalar };
	my $argc = scalar(@argv);
	my $request;

	if ($argc == 1)
	{
		$client->writeConsoleOutput(text =>
				"Usage: reg_enumvalue [key path]\n");
		goto out;
	}

	# Create the sys_reg_enumvalue request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "sys_reg_enumvalue");
	
	# Add TLV
	$request->addTlv(
			type  => Def::TLV_TYPE_REGISTRY_KEY_PATH,
			value => $argv[1]);

	# Transmit
	$client->transmitPacket(
			packet            => \$request,
			completionHandler => \&regEnumValueComplete);

out:
	return 1;
}

1;
