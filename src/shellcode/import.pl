#!/usr/bin/perl
###############
##
#
# Shellcode auto-importing tool for MSF.  Takes raw payloads
# and converts them to perl modules.
#
##
###############

use strict;
use FindBin qw($RealBin);
use POSIX;

my $payloadDirectory = $RealBin . "/../../payloads/";
my @payloads  = ();
my $platforms = 
	{
		'i686'            => 'ia32',
		'i586'            => 'ia32',
		'i486'            => 'ia32',
		'i386'            => 'ia32',
		'sun4m'           => 'sparc',
		'sun4u'           => 'sparc',
		'sparc'           => 'sparc',
		'Power Macintosh' => 'ppc',
		'alpha'           => 'alpha',
	};
my @uinfo = POSIX::uname();
my $mach  = $uinfo[4];
my $arch  = $platforms->{$mach};

print "Loading payloads...\n";

LoadPayloads();

print "Loaded " . scalar(@payloads) . " payloads.\n";

TranslatePayloads();

exit;

#
# Subs
#

#
# Loads all compatible payloads for translation
#
sub LoadPayloads
{
	RecurseDirectoryForPayloads(directory => $RealBin);
}

#
# Recurses the shellcode directory looking for payloads to import on the
# platform being executed on
#
sub RecurseDirectoryForPayloads
{
	my ($directory) = @{{@_}}{qw/directory/};
	my @sub;

	return undef if (!opendir(DIR, $directory));

	@sub = readdir(DIR);

	foreach my $child (@sub)
	{
		my $path = "$directory/$child";

		# If the path is a directory and it does not start with a slash, recurse
		if ((-d $path) and
		    (!($child =~ /^\./)))
		{
			RecurseDirectoryForPayloads(directory => $path);
		}
		# If the path is a file and it ends in '.asm', add it to the list of
		# payloads
		elsif ((-f $path) and
		       ($path =~ /(.*)\.asm$/))
		{
			my $path = $1;

			# Skip architectures we don't support
			next if (!($path =~ /$arch/));

			push @payloads, 
				{
					source   => $path . ".asm",
					hex      => $path . ".hex",
					raw      => $path . ".o",
					disasm   => $path . ".disasm",
					template => $path . ".template",
				};
		}
	}

	closedir(DIR);
}

#
# Translate payloads from source/raw information into perl modules
#
sub TranslatePayloads
{
	# Enumerate through all of the payloads
	foreach my $payload (@payloads)
	{
		my $meta;
		my $name;
	
		# Get the payloads meta information for use with translation
		$meta = ExtractMetaInformation(
			payload => $payload);

		next if (not defined($meta));

		if ((defined($meta->{'category'})) and
		    ($meta->{'category'} eq 'stager'))
		{
			print "Skipping stager import until better support is added.\n";
			next;
		}

		if ((defined($meta->{'importable'})) and
		    ($meta->{'importable'} eq 'no'))
		{
			print "Skipping non-importable payload: " . $payload->{'source'} . "\n";
			next;
		}
		
		# Get the payload's translated file name based on the meta information
		$name = GetPayloadName(
			meta => $meta);

		if (not defined($name))
		{
			print STDERR "Failed to determine translated filename for payload: " . $payload->{'source'} . "\n";
			next;
		}

		next if (!TranslatePayload(
			name    => $name,
			meta    => $meta,
			payload => $payload));
		
		print "Translated $name\n";
	}
}

#
# Extract information about how the payload should be imported from the source
# file
#
sub ExtractMetaInformation
{
	my ($payload) = @{{@_}}{qw/payload/};
	my $info;

	# Open the payload's source file
	if (!open(SOURCE, $payload->{'source'}))
	{
		print STDERR "Failed to open payload: " . $payload->{'source'} . "\n";
		return undef;
	}

	# Enumerate the lines of the source file
	while (<SOURCE>)
	{
		my $value;
		my $tag;

		chomp($_);

		next if (!($_ =~ /META-(.+)=(.*)$/i));

		$tag   = $1;
		$value = $2;

		$info->{lc($tag)} = $value;
	}

	# Close source, baby!
	close(SOURCE);

	return $info;
}

#
# Gets a payload's translated file name from its meta information
#
sub GetPayloadName
{
	my ($meta)   = @{{@_}}{qw/meta/};
	my $filename = undef;
	my $category = $meta->{'category'};
	my $arch     = $meta->{'arch'};
	my $name     = $meta->{'name'};
	my $os       = $meta->{'os'};

	# Check to see if we have enough information to build the translated 
	# filename
	if ((not defined($arch)) or
	    (not defined($os)) or
	    (not defined($category)) or
	    (not defined($name)))
	{
		return undef;
	}

	return $os . "_" . $arch . "_" . $category . "_" . $name;
}

#
# Translates an individual payload into a perl module
#
sub TranslatePayload
{
	my ($name, $meta, $payload) = @{{@_}}{qw/name meta payload/};
	my $filename;
	my $authorList = "";
	my $contents = "";
	my @authors;

	if (defined($meta->{'path'}))
	{
		$filename = $meta->{'path'};
	} 
	else
	{
		$filename = $payloadDirectory . $name . ".pm";
	}

	# Translate the authors into a list for use in the perl module
	if (defined($meta->{'authors'}))
	{
		@authors = split /,/, $meta->{'authors'};

		foreach (@authors)
		{
			$authorList .= "'$_', ";
		}
	}

	# Open the module file
	if (!open(MODULE, ">$filename"))
	{
		print STDERR "Failed to open module file for writing: $filename\n";
		return 0;
	}

	# If a template file exists, use it
	if (-f $payload->{'template'})
	{
		$contents = BuildPayloadFromCustomTemplate(
			name    => $name,
			meta    => $meta,
			payload => $payload,
			authors => $authorList);
	}
	else
	{
		$contents = BuildPayloadFromStandardTemplate(
			name    => $name,
			meta    => $meta,
			payload => $payload,
			authors => $authorList);
	}

	# Write the module to the file and close, we win
	print MODULE $contents;

	close(MODULE);

	return 1;
}

#
# Build the payload from a template file rather than from the standard template
#
sub BuildPayloadFromCustomTemplate
{
	my ($name, $meta, $payload, $authors) = @{{@_}}{qw/name meta payload authors/};
	my $contents = "";
	my $disasm = GetPayloadDisassembly(
		payload => $payload);
	my $hex = GetPayloadHexString(
		payload => $payload);
	my $shortname = $meta->{'shortname'};
	my $description = $meta->{'description'};
	my $arch = $meta->{'arch'};
	my $os = $meta->{'os'};

	if (!open(TEMPLATE, $payload->{'template'}))
	{
		printf STDERR "Failed to open template file: " . $payload->{'template'} . "\n";
		return undef;
	}

	while (<TEMPLATE>)
	{
		$contents .= $_;
	}

	close(TEMPLATE);

	# Replace template variables
	$contents =~ s/__NAME__/$name/gm;
	$contents =~ s/__SHORTNAME__/$shortname/gm;
	$contents =~ s/__DESCRIPTION__/$description/gm;
	$contents =~ s/__ARCH__/$arch/gm;
	$contents =~ s/__OS__/$os/gm;
	$contents =~ s/__AUTHORS__/$authors/gm;
	$contents =~ s/__HEX__/$hex/gm;
	$contents =~ s/__DISASM__/$disasm/gm;

	# Enumerate through all the custom defined variables
	my $index = 1;
	my $val;

	while (defined($val = $meta->{"custom$index"}))
	{
		my $var = "__CUSTOM" . $index . "__";

		$contents =~ s/$var/$val/gm;

		$index++;
	}

	return $contents;
}

#
# Build the payload from the standard template
#
sub BuildPayloadFromStandardTemplate
{
	my ($name, $meta, $payload, $authors) = @{{@_}}{qw/name meta payload authors/};
	my $contents = '';

	# Build out the module's contents
	$contents .=
"
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::$name;
use strict;
";

	# Does this payload have a base module from which it should inherit
	if (defined($meta->{'basemod'}))
	{
		$contents .=
"use base '" . $meta->{'basemod'} . "';\n";
	}

	$contents .=
"
my \$info =
{
	'Name'        => '" . $meta->{'shortname'} . "',
	'Version'     => '\$" . "Revision: " . "1.0 \$',
	'Description' => '" . $meta->{'description'} . "',
	'Authors'     => [ $authors ],
	'Priv'        => 0,
	'Size'        => 0,
	'Arch'        => [ '" . $meta->{'arch'} . "' ],
	'OS'          => [ '" . $meta->{'os'} . "' ],
};

sub new
{
	my \$class = shift;
	my \$hash  = \@_ ? shift : { };

	\$hash = \$class->MergeHashRec(\$hash, { 'Info' => \$info });

	my \$self = \$class->SUPER::new(\$hash, \@_);

	\$self->_Info->{'Size'} = \$self->_GenSize;

	return \$self;
}
";

	# Get the Build, Generate, and GenSize functions that are specific to a 
	# given category
	$contents .= GetCategorySpecificModuleContents(
		meta    => $meta,
		payload => $payload);
	
	$contents .= 
"
1;
";

	return $contents;
}

#
# Get contents that are specific to a given type of payload
#
sub GetCategorySpecificModuleContents
{
	my ($meta, $payload) = @{{@_}}{qw/meta payload/};
	my $connectionType = $meta->{'connection-type'};
	my $category = $meta->{'category'};
	my $contents = "";
	my $hex = GetPayloadHexString(
		payload => $payload);

	# If the payload is connection based...
	if (defined($connectionType))
	{
		my $offsets = 
			{
				LHOST   => $meta->{'offset-lhost'},
				LPORT   => $meta->{'offset-lport'},
				RHOST   => $meta->{'offset-rhost'},
				RPORT   => $meta->{'offset-rport'},
				CPORT   => $meta->{'offset-cport'},
				FINDTAG => $meta->{'offset-findtag'},
			};

		if ($connectionType eq 'reverse')
		{
			$contents = 
"
sub Build
{
	my \$self = shift;
	return \$self->Generate(
		\$self->GetVar('LHOST'), 
		\$self->GetVar('LPORT'));
}

sub Generate
{
	my \$self = shift;
	my \$host = shift;
	my \$port = shift;
	my \$port_bin = pack('n', \$port);
	my \$host_bin = gethostbyname(\$host);

	my \$shellcode = 
$hex;	

	substr(\$shellcode, " . $offsets->{'LPORT'} . ", 2, \$port_bin);
	substr(\$shellcode, " . $offsets->{'LHOST'} . ", 4, \$host_bin);

	return \$shellcode
}

sub _GenSize
{
	my \$self = shift;
	my \$bin  = \$self->Generate('127.0.0.1', '4444');
	return length(\$bin);
}
";
		}
		elsif ($connectionType eq 'bind')
		{
			$contents = 
"
sub Build
{
	my \$self = shift;
	return \$self->Generate(
		\$self->GetVar('LPORT'));
}

sub Generate
{
	my \$self = shift;
	my \$port = shift;
	my \$port_bin = pack('n', \$port);

	my \$shellcode =
$hex;

	substr(\$shellcode, " . $offsets->{'LPORT'} . ", 2, \$port_bin);

	return \$shellcode;
}

sub _GenSize
{
	my \$self = shift;
	my \$bin = \$self->Generate('4444');
	return length(\$bin);
}
";
		}
		elsif ($connectionType eq 'findtag')
		{
			$contents = 
"
sub Build
{
	my \$self = shift;
	return \$self->Generate();
}

sub Generate
{
	my \$self = shift;
	my \$tag  = substr(\$self->GetLocal('FindTag') . (\"\\x01\" x 0x4), 0, 4);

	my \$shellcode =
$hex;

	substr(\$shellcode, " . $offsets->{'FINDTAG'} . ", 4, \$tag);

	return \$shellcode;
}

sub _GenSize
{
	my \$self = shift;
	my \$bin  = \$self->Generate();
	return length(\$bin);
}
";
		}
	}
	else
	{
		$contents =
"
sub Build
{
	my \$self = shift;
	return \$self->Generate();
}

sub Generate
{
	my \$self = shift;

	my \$shellcode =
$hex;

	return \$shellcode;
}

sub _GenSize
{
	my \$self = shift;
	my \$bin  = \$self->Generate();
	return length(\$bin);
}
";
	}

	# Include the payload disassembly
	$contents .= GetPayloadDisassembly(
		payload => $payload);

	return $contents;
}

#
# Get the payload's hex string that is formatted for inclusion in a perl module
#
sub GetPayloadHexString
{
	my ($payload) = @{{@_}}{qw/payload/};
	my $hex = '';

	if (!open(HEX, $payload->{'hex'}))
	{
		print STDERR "Failed to open payload hex: " . $payload->{'hex'} . "\n";
		return undef;
	}

	while (<HEX>)
	{
		chomp($_);

		$hex .= " .\n" if (length($hex));
		$hex .= "\t\t\"$_\"";
	}

	close HEX;

	return $hex;
}

#
# Get the disassembly output for the payload and include it in the translated
# version
#
sub GetPayloadDisassembly
{
	my ($payload) = @{{@_}}{qw/payload/};
	my $disasm;

	if (!open(DISASM, $payload->{'disasm'}))
	{
		print STDERR "Failed to open payload disasm: " . $payload->{'disasm'} . "\n";
		return undef;
	}

	$disasm = "\n# Disassembly:\n#\n";

	while (<DISASM>)
	{
		chomp($_);

		$disasm .= "# $_\n";
	}

	return $disasm;
}
