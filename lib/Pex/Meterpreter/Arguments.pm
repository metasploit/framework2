
###############
##
#
#    Name: Arguments.pm
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
#      This module implements ``getopt'' in perl land.  There are probably other
#      implementations out there, but oh well.  There are a number of
#      limitations in this approach, so it isn't a true getopt implementation.
#      Eventually I'll go back and pimp it out.
#
##
###############

package Pex::Meterpreter::Arguments;

use strict;

sub new
{
	my $this  = shift;
	my $class = ref($this) || $this;
	my $self  = {};
	my ($argv, $fmt) = @{{@_}}{qw/argv fmt/};

	bless($self, $class);

	# Initialize attributes
	$self->reset(argv => $argv, fmt => $fmt);

	return $self;
}

#
# Resets the context
#
sub reset
{
	my $self = shift;
	my ($argv, $fmt) = @{{@_}}{qw/argv fmt/};

	# Initialize attributes
	$self->{'argv'}     = $argv;
	$self->{'fmt'}      = $fmt;

	$self->{'index'}    = 0;
	$self->{'toggle'}   = undef;
	$self->{'argument'} = undef;
}

#
# Parses the argument vector at the current index
#
sub parse
{
	my $self  = shift;
	my @argv  = @{ $self->{'argv'} };
	my $index = $self->{'index'};
	my $items = scalar(@argv);
	my $fmt   = $self->{'fmt'};
	my $first;
	my $second;

	return undef if ($index >= $items);

	$first  = substr($argv[$index], 0, 1);
	$second = substr($argv[$index], 1, 1);

	if ($first eq '-')
	{
		my $offset = 0;
		my $toggle;

		# Enumerate through the format string
		while (defined($toggle = substr($fmt, $offset, 1)))
		{
			my $hasParam = substr($fmt, $offset + 1, 1);

			if ($toggle eq $second)
			{
				if (($hasParam eq ':') and
				    ($index + 1 < $items))
				{
					$self->{'argument'} = $argv[$index + 1];

					$index++;
				}
			
				$self->{'toggle'} = $toggle;

				last;
			}

			$offset++;
		}
	}
	else
	{
		$self->{'toggle'} = 0;
	}

	$self->{'index'} = $index + 1;

	return $self->{'toggle'};
}

sub getArgument
{
	my $self = shift;

	return $self->{'argument'};
}

1;
