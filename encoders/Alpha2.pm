
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::Alpha2;
use strict;
use base 'Msf::Encoder::SkyAlphaNum';
use Pex::Encoder;

my $advanced = {
  'ForceUpper' => [0, 'Don\'t even try mixed-case, force upper-case'],
  'NoCompress' => [0, 'Use uncompressed stubs'],
};

my $info = {
  'Name'    => 'Skylined\'s Alpha2 Alphanumeric Encoder',
  'Version' => '1.0',
  'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],
  'Arch'    => [ 'x86' ],
  'OS'      => [ ],
  'Description'  =>  "Skylined's alphanumeric encoder ported to perl",
  'Refs'    => [ ],
  'Keys'    => [ 'alphanum' ],
  'UserOpts' => {
    'GETPCTYPE' => ['geteip', 'BaseAddr for geteip'],
  },
};

sub new {
  my $class = shift; 
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

#
# This code is a port of Skylined's awesome alpha encoder
#
sub EncodePayload {
  my $self = shift;
  my $rawshell = shift;
  my $badChars = shift;

  my $type = $self->GetVar('GETPCTYPE');
  my $upper = $self->GetLocal('ForceUpper');
  my $noCompress = $self->GetLocal('NoCompress');
  my $prepend = '';

  # notice geteip != seh, geteip will use a os-independant geteip
  if(!defined($type) || $type eq 'geteip') {
    $self->PrintDebugLine(5, 'Trying an os-independant geteip (not alphanum)');
    $prepend = $self->_FindGetEip($badChars);
    if(!defined($prepend)) {
      $self->PrintDebugLine(3, 'Could not find a useable geteip');
      return;
    }
    $type = 'ecx'; # use ecx for a geteip prepend.
#    $self->PrintDebugLine(5, 'Found useable geteip ' . $prepend);
  }
  
  my $lowerChars = join('', 'a' .. 'z');
  if(!$upper && Pex::Text::BadCharCheck($badChars, $lowerChars)) {
    $self->PrintDebugLine(5, 'Lower case characters in badChars, trying upper case');
    $upper = 1;
  }

  my $encoderType = $upper ? 'upper' : 'mixed';

  if($noCompress) {
    $encoderType .= 'Nocompress';
  }

  $self->PrintLine("Trying $encoderType");
  my $decoder = $self->_Encode($rawshell, $encoderType, $type);
  return if(!defined($decoder));

  return($prepend . $decoder);
}

sub _FindGetEip {
  my $self = shift;
  my $badChars = shift;

  my @getEips = (
    "\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff",
    # if it doesnt work, use this behemoth with minimized chars
    # unique chars: 59 EB E8 A4 FF
    "\xeb\x59\x59\x59\x59\xeb\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59".
    "\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59".
    "\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59".
    "\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59".
    "\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59".
    "\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\xe8\xa4\xff\xff\xff",
  );

  foreach my $getEip (@getEips) {
    if(Pex::Text::BadCharCheck($badChars, $getEip)) {
      $self->PrintDebugLine(5, 'Badchar in geteip');
    }
    else {
      return($getEip)
    }
  }

  $self->PrintDebugLine(5, 'Exhausted getEips, none w/o badChars');
  return;
}

1;
