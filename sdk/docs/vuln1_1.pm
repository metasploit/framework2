
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::vuln1_1;
use strict;
use base 'Msf::Exploit';
use Msf::Socket::Tcp;
use Pex::Text;

my $advanced = {
};

my $info = {
  'Name'    => 'Vuln1 v1 Exploit',
  'Version'  => '$Revision$',

  # List of authors, your's truely
  'Authors' => [ 'spoonm', ],

  # The following options are used to match payloads with the exploit.
  # Architectures supported
  'Arch'    => [ 'x86' ],

  # Operating Systems supported
  'OS'      => [ 'linux' ],

  # This advertises whether the exploit gains a priviledges account
  # after successful exploitation.  1 means that it does (ie SYSTEM or root)
  # This is used incase a payload needs priviledged access to successfully
  # operate (ie adduser)
  'Priv'    => 1,

  # Tell the framework to ask the users for these options, in the format of
  # BOOL (required/optional), Type, and Description
  'UserOpts'  =>
    {
      # RHOST and RPORT are our standard names for remote host and port
      # The framework will resolve any hostnames passed in for you, so you
      # will get an ip address always from RHOST (because it is type ADDR)
      'RHOST' => [1, 'ADDR', 'The target address'],

      # Default to port to 11221, the port vuln1.c listens on
      'RPORT' => [1, 'PORT', 'The target port', 11221],
    },

  # Freeform is our freeform style text parser, allowing you to have arbitrary
  # line breaks, making for text that looks good both in source and in output
  'Description'  => Pex::Text::Freeform(qq{
    I am a banana

    Awww yeah
    }),
  'Refs'  =>
    [
      'http://www.metasploit.com',
    ],
};

# This is our standard (and necessary) new method, informing the Framework
# of information like the Info hash and Advanced Options
sub new {
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

  return($self);
}

# We could add a check w/ a Check method much like Exploit, but we are lazy
# for now


# The Exploit method gets called by the framework when a user runs the exploit
sub Exploit {
  my $self = shift;

  # Pull the user supplied RHOST/RPORT values.  RHOST will be resolved
  # into an IP address
  my $targetHost  = $self->GetVar('RHOST');
  my $targetPort  = $self->GetVar('RPORT');

  # Create the TCP socket
  my $sock = Msf::Socket::Tcp->new(
    'PeerAddr' => $targetHost,
    'PeerPort' => $targetPort,
  );
  if($sock->IsError) {
    $self->PrintLine('Error creating socket: ' . $sock->GetError);
    return;
  }

  # PatternCreate sends a stream of different characters which we can use
  # to calculate distance to something like EIP
  $sock->Send(Pex::Text::PatternCreate(200));

  return;
}

# Always end your perl modules with a 1
1;
