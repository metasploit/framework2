
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::PexAlphaNum;
use strict;
use base 'Msf::Encoder';
use Pex::Encoder;

my $advanced = {
  'PexDebug' => [0, 'Sets the Pex Debugging level (zero is no output)'],
};

my $info = {
  'Name'    => 'Pex Alphanumeric Encoder',
  'Version' => '1.0',
  'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],
  'Arch'    => [ 'x86' ],
  'OS'      => [ ],
  'Description'  =>  "Skylined's alphanumeric encoder ported to perl",
  'Refs'    => [ ],
  'Keys'    => [ 'alphanum' ],
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
  if (! $type && $self->GetVar('_Payload') && grep {/win32/} @{ $self->GetVar('_Payload')->OS})
  {
    $type = 'win32';
  }

  # Begin hd-written foo

    my $prepend = "";
    
    if (! $type)
    {
        # the prepend chunks leave ecx=end of code
        $type    = 'ecx';
        
        # use a somewhat sane small prepend first
        $prepend = "\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff";
        
        # if it doesnt work, use this behemoth with minimized chars
        if (Pex::Text::CharsInBuffer($prepend, $badChars))
        {
            # unique chars: 59 EB E8 A4 FF
            $prepend = 
            "\xeb\x59\x59\x59\x59\xeb\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59".
            "\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59".
            "\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59".
            "\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59".
            "\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59".
            "\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\xe8\xa4\xff\xff\xff";
        }
    }

    # the decoder in all its glory (hardcoded for 9 byte baseaddr)
    my $decoder = 'VTX630VX4A0B6HH0B30BCVX2BDBH4A2AD0ADTBDQB0ADAVX4Z8BDJOM';
    my $encoded;
    
    my $allowed = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXY';
    
    # first check to see if the encoder/alphabet is allowed 
    if ( Pex::Text::CharsInBuffer($allowed.$decoder.'Z', $badChars) )
    {
        $self->PrintDebugLine(3, 'Encoder failed: restricted character in decoder or alphabet');
        return;
    }
    
    # the different places where our baseaddr is stored by getpc
    my %baseaddr;
    $baseaddr{'eax'}    = 'PZJJJJJRY';
    $baseaddr{'ebx'}    = 'SZJJJJJRY';
    $baseaddr{'ecx'}    = 'OIIIIIIQZ';
    $baseaddr{'edx'}    = 'OJJJJJJRY';
    $baseaddr{'esp'}    = 'TZJJJJJRY';
    $baseaddr{'ebp'}    = 'UZJJJJJRY';
    $baseaddr{'esi'}    = 'VZJJJJJRY';
    $baseaddr{'edi'}    = 'WZJJJJJRY';
    $baseaddr{'win32'}  = $baseaddr{'ecx'};

    if (! exists($baseaddr{$type}))
    {
        $self->PrintDebugLine(3, "Encoder failed: invalid type specified ($type)");
        return;
    }

    my $win32getpc = 'VTX630VXH49HHHPhYAAQhZYYYYAAQQDDDd36FFFFTXVj0PPTUPPa301089';
    
    if ($type eq 'win32' && ! Pex::Text::CharsInBuffer($baseaddr{'win32'}.$win32getpc, $badChars))
    {
        $encoded = $win32getpc . $baseaddr{'win32'} . $decoder;
    } 
    else 
    {
        $encoded = $baseaddr{$type} . $decoder;
    }

    my @alphanum = split(//, $allowed);
    my (@lonibs, @hinibs);

    foreach my $x (0 .. 255)  {
    foreach my $y (@alphanum) {
        $lonibs[$x] = (($x & 0x0f) ^ 0x41) + 1;

        if (($x & 0xf0) >> 4 == (ord($y) & 0x0f))
        {
            push @{$hinibs[$x]}, $y;
        }
    } }


    foreach (split(//, $rawshell))
    {
        my $nibL = chr($lonibs[ord($_)]);
        my $nibH = @{$hinibs[ord($_)]}[ rand @{$hinibs[ord($_)]} ];
        $encoded .= $nibL . $nibH;
    }
    $encoded .= "Z";
    return($prepend.$encoded);
}

1;
