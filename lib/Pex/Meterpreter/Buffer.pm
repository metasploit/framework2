
###############
##
#
#    Name: Buffer.pm
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
#      This module implements buffer serialization.
#
##
###############

package Pex::Meterpreter::Buffer;

use strict;

sub new
{
	my $this  = shift;
	my $class = ref($this) || $this;
	my $self  = {};
	my ($filePath) = @{{@_}}{qw/filePath/};

	bless($self, $class);

	# Initialize attributes
	$self->{'data'} = undef;

	if (defined($filePath))
	{
		if (not defined($self->fromFile(path => $filePath)))
		{
			$self = undef;
		}
	}

	return $self;
}

#
# Get the data buffer
# 
sub getData
{
	my $self = shift;

	return $self->{'data'};
}

#
# Read the contents of a file into the buffer
#
sub fromFile
{
	my $self = shift;
	my ($path) = @{{@_}}{qw/path/};
	my $f;

	# No escaping necessary!

	if (defined(open($f, "<$path")))
	{
		binmode($f);

		$self->{'data'} = '';

		while (<$f>)
		{
			$self->{'data'} .= $_;
		}
	}

	return $self->{'data'};
}

1;
