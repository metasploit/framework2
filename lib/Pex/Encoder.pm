#!/usr/bin/perl
###############

##
#         Name: Encoder.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::Encoder;
use strict;
use Pex::Text;


#
# This routine is used by the Framework to automatically
# encode a given payload so that the specified "bad" bytes
# are not in the end result. Currently it just uses juliano's
# really sweet key scanner algorithm, in the future it will
# dynamically generate and encode the encoder as well :)
#

my $encoders = {
  'Dispatcher' => \&DefaultDispatcher,
  'x86' => { 
    'DWord Xor' => {
      'Dispatcher'  => \&DWordXorDispatcher,
      'JmpCall'     => ['Variable length 26/29 byte Jmp/Call encoder', \&XorDecoderDwordJmpCall],
      'Fnstenv Sub' => ['Variable length 26/29 byte Fnstenv encoder', \&XorDecoderDwordFnstenvSub],
      'Fnstenv Mov' => ['Variable Length 23/25 byte Fnstenv encoder', \&XorDecoderDwordFnstenvMov],
    },
    'AlphaNum' => {
      'Skylined' => ['Skylined\'s AlphaNumerica encoder', \&EncodeAlphaNum],
    },
#    'Byte Xor' => {
#      'Fnstenv Sub' => ['25 byte Fnstenv encoder', \&XorDecoderByte],
#    },
  },
  'sparc' => {
    'Fake' => {
      'Tester' => ['Just testing baby, just testing', ],
    },
  },
};

# Returns array reference
sub GetEncoders {
  my $arch = shift;
  my $type = shift;
  my $name = shift;
  my $dispatch = DispatchList($arch, $type, $name);
  my $encs = [ ];
  foreach my $encoder (@{$dispatch}) {
    push(@{$encs}, [ @{$encoder->[2]}, $encoder->[1]->[0] ]);
  }
  return($encs);
}

# Yeah yeah, I'll get around to it
sub GetEncodersHash {
}

sub Encode {
  my $arch = shift;
  my $type = shift;
  my $name = shift;
  my ($rawshell, $badChars, $debug) = @_;
  my @args = @_; # args (maybe encoder specific)


  my $dispatch = DispatchList($arch, $type, $name);

  foreach my $encoder (@{$dispatch}) {
#    print $encoder->[1]->[1];
#    print "\n" . join(' ', @{$encoder->[2]}) . "\n";
    my @encoderName = @{$encoder->[2]};
    print "Trying @encoderName\n" if($debug);
    my $encoded = &{$encoder->[0]}(@encoderName, $encoder->[1]->[1], @args);

    # If you are using this with msf, this check will happen again inside of
    # the framework, but the check remains for standalone pex usage
    # sanity checking, this should never happen
    if(Pex::Text::CharsInBuffer($encoded, $badChars)) {
      print "Caught bad chars in @encoderName\n" if($debug);
    }
    else {
      return($encoded);
    }
  }
  return;
}

sub DispatchList {
  my $arch = shift;
  my $type = shift;
  my $name = shift;

  my $dispatch;

  # ugly, sorry
  my $dispatcher = $encoders->{'Dispatcher'};
  if($arch) {
    my $earch = $encoders->{$arch} || { };
    my $dispatcher = $earch->{'Dispatcher'} || $dispatcher;
    if($type) {
      my $etype = $earch->{$type} || { };
      my $dispatcher = $etype->{'Dispatcher'} || $dispatcher;
      if($name) {
        return if(!$etype->{$name});
        $dispatch = DispatchHelper({ $name, $etype->{$name} }, $dispatcher, $arch, $type);
      }
      else {
        $dispatch = DispatchHelper($etype, $dispatcher, $arch, $type);
      }
    }
    else {
      $dispatch = DispatchHelper($earch, $dispatcher, $arch);
    }
  }
  else {
    $dispatch = DispatchHelper($encoders, $dispatcher);
  }
  return($dispatch);
}

sub DispatchHelper {
  my $hash = shift;
  my $dispatcher = shift;
  my @args = @_;
  my $dispatch = [ ];
  foreach my $key (keys(%{$hash})) {
    next if($key eq 'Dispatcher');
    my $val = $hash->{$key};
    my $dispatcher = $hash->{'Dispatcher'} || $dispatcher;

    if(ref($val) eq 'HASH') {
      push(@{$dispatch}, @{DispatchHelper($val, $dispatcher, @args, $key)});
    }
    else {
      push(@{$dispatch}, [ $dispatcher, $val, [@args, $key] ]);
    }
  }
  return($dispatch);
}

sub DefaultDispatcher {
  my $arch = shift;
  my $type = shift;
  my $name = shift;
  my $encoder = shift;
  my $rawshell = shift;
  my $badChars = shift;
  my $debug =  shift;
  my @extraArgs = @_;

  print "DefaultDispatcher called to use $arch -> $type -> $name\n" if($debug);
  return(&{$encoder}($rawshell, $badChars, $debug, @extraArgs));
}

sub DWordXorDispatcher {
  my $arch = shift;
  my $type = shift;
  my $name = shift;
  my $encoder = shift;
  my $rawshell = shift;
  my $badChars = shift;
  my $debug =  shift;
  my @extraArgs = @_;

  print "DWordXorDispatcher Called to use $arch -> $type -> $name\n" if($debug);

  my $xorkey = XorKeyScanDword($rawshell, $badChars);
    
    if (! $xorkey)
    {
        print "Could not locate valid xor key\n" if($debug);
        return;
    }
    
    my $xordat = XorDword($xorkey, $rawshell);
    my $encode = &{$encoder}($xorkey, length($xordat), $badChars, @extraArgs);
    my $shellcode = $encode . $xordat;
    return($shellcode);
}


#
# This code is a port of Skylined's awesome alpha encoder
#
sub EncodeAlphaNum {
    my ($rawshell, $xbadc, $debug, $type) = @_;
    my $prepend = "";
    
    if (! $type)
    {
        # the prepend chunks leave ecx=end of code
        $type    = 'ecx';
        
        # use a somewhat sane small prepend first
        $prepend = "\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff";
        
        # if it doesnt work, use this behemoth with minimized chars
        if (Pex::Text::CharsInBuffer($prepend, $xbadc))
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
    if ( Pex::Text::CharsInBuffer($allowed.$decoder.'Z', $xbadc) )
    {
        print "Encoder failed: restricted character in decoder or alphabet\n" if($debug);
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
        print "Encoder failed: invalid type specified ($type)\n" if($debug);
        return;
    }

    my $win32getpc = 'VTX630VXH49HHHPhYAAQhZYYYYAAQQDDDd36FFFFTXVj0PPTUPPa301089';
    
    if ($type eq 'win32' && ! Pex::Text::CharsInBuffer($baseaddr{'win32'}.$win32getpc, $xbadc))
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

#
# These are the current x86 decoders, all of them are static
# at the moment, but tend to meet the needs of most exploits.
#

sub XorDecoderDwordAntiIds {
    my ($arch, $xor, $len, $xbadc) = @_;
    if(! $len) { $len = 0x200 }

    
    if (lc($arch) eq "x86")
    {
        # this xor decoder was written by spoonm <ninjatools [at] hush.com>
	    my $smallVersion = 0;
        
        # Pad to a 4 byte boundary, the xor data should already be padded
        # but just incase.
        my $loopCounter = int(($len - 1) / 4) + 1;
        $loopCounter *= -1;

        my $xorlen = pack("V", $loopCounter);
        my $xorkey = pack("V", $xor);
        

        # this anti-0xff encoder written by hdm [at] metasploit.com
        if (index($xbadc, "\xff") != -1)
        {

            # try sub len, then add len
            my $loopmode = "sub";
            my $lenops = "\x66\x81\xe9";
            $xorlen = pack("v", $loopCounter);
            
            if (Pex::Text::CharsInBuffer($xorlen, $xbadc))
            {
                $xorlen = pack("v", abs($loopCounter));
                $lenops = "\x66\x81\xc1";
                $loopmode = "add";
            }
            
            if (Pex::Text::CharsInBuffer($xorlen, $xbadc) && $loopCounter < 128)
            {
                $xorlen = chr(abs($loopCounter)) . "\x59\x90\x90";
                $lenops = "\x6a";
                $loopmode = "push";
            }
            
            if (! Pex::Text::CharsInBuffer($xorlen, $xbadc))
            {
                my $decoder = 
                "\xd9\xe1".                 # fabs
                "\xd9\x34\x24".             # fnstenv (%esp,1)
                "\x5b".                     # pop    %ebx
                "\x5b".                     # pop    %ebx
                "\x5b".                     # pop    %ebx
                "\x5b".                     # pop    %ebx
                "\x80\xc3\x1f".             # add    $0x1f,%ebx
                "\x31\xc9".                 # xor    %ecx,%ecx
                $lenops . $xorlen.          # stick loop cnt into ecx
                "\x81\x33" .$xorkey.        # xorl   $0x69696969,(%ebx)
                "\x43".                     # inc    %ebx
                "\x43".                     # inc    %ebx
                "\x43".                     # inc    %ebx
                "\x43".                     # inc    %ebx
                "\xe2\xf4";                 # loop   a0000013 <_start+0x13>
                return $decoder;
            }
        }
    }
}

# Variable Length Decoder Using jmp/call 26/29 bytes.
# Uses smaller encoder if payload is <= 512 bytes
sub XorDecoderDwordJmpCall {
  my $xor = shift;
  my $len = shift;
  my $xorkey = pack('V', $xor);
  my $l = PackLength($len);

  # spoon's smaller variable-length encoder
  my $decoder;
  if($l->{'negSmall'}) {
    # 26 bytes
    $decoder =
      "\xeb\x13".                         # jmp SHORT 0x15 (xor_end)
      "\x5e".                             # xor_begin: pop esi
      "\x31\xc9".                         # xor ecx,ecx
      "\x83\xe9". $l->{'negLengthByte'} . # sub ecx, BYTE -xorlen
      "\x81\x36". $xorkey .               # xor_xor: xor DWORD [esi],xorkey
      "\x83\xee\xfc".                     # sub $esi,-4
      "\xe2\xf5".                         # loop 0x8 (xor_xor)
      "\xeb\x05".                         # jmp SHORT 0x1a (xor_done)
      "\xe8\xe8\xff\xff\xff";             # xor_end: call 0x2 (xor_begin)
                                          # xor_done:
  }
  else {
    # 29 bytes
    $decoder =
      "\xeb\x16".                         # jmp SHORT 0x18 (xor_end)
      "\x5e".                             # xor_begin: pop esi
      "\x31\xc9".                         # xor ecx,ecx
      "\x81\xe9". $l->{'negLength'} .     # sub ecx, -xorlen
      "\x81\x36". $xorkey .               # xor_xor: xor DWORD [esi],xorkey
      "\x83\xee\xfc".                     # sub $esi,-4
      "\xe2\xf5".                         # loop 0xb (xor_xor)
      "\xeb\x05".                         # jmp SHORT 0x1d (xor_done)
      "\xe8\xe5\xff\xff\xff";             # xor_end: call 0x2 (xor_begin)
                                          # xor_done:
  }

  return $decoder;
}

# w00t http://archives.neohapsis.com/archives/vuln-dev/2003-q4/0096.html
# This is useful if you have a BadChar of say 0xff, and your payload is small (or insanely large)
# enough to not have 0xff in your payload, which is realistic (<= 512 && > 4)
sub XorDecoderDwordFnstenvSub {
  my $xorkey = pack('V', shift());
  my $l = PackLength(shift());


  # spoon's smaller variable-length fnstenv encoder
  my $decoder;
  if($l->{'negSmall'}) {
    # 24 bytes
    $decoder =
      "\xd9\xee".                         # fldz
      "\xd9\x74\x24\xf4".                 # fnstenv [esp - 12]
      "\x5b".                             # pop ebx
      "\x31\xc9".                         # xor ecx,ecx
      "\x83\xe9". $l->{'negLengthByte'} . # sub ecx, BYTE -xorlen
      "\x81\x73\x18". $xorkey .           # xor_xor: xor DWORD [ebx + 24], xorkey
      "\x83\xeb\xfc".                     # sub ebx,-4
      "\xe2\xf4"                          # loop xor_xor
  }
  else {
    # 27 bytes
    $decoder =
      "\xd9\xee".                         # fldz
      "\xd9\x74\x24\xf4".                 # fnstenv [esp - 12]
      "\x5b".                             # pop ebx
      "\x31\xc9".                         # xor ecx,ecx
      "\x81\xe9". $l->{'negLength'} .     # sub ecx, -xorlen
      "\x81\x73\x1b". $xorkey .           # xor_xor: xor DWORD [ebx + 27], xorkey
      "\x83\xeb\xfc".                     # sub ebx,-4
      "\xe2\xf4"                          # loop xor_xor
  }
  return $decoder;
}

# 23 for payloads <= 1020 bytes and 25 for <= 262140 bytes (yeah, that should never happen)
sub XorDecoderDwordFnstenvMov {
  my $xor = shift;
  my $len = shift;
  my $xorkey = pack('V', $xor);
  my $l = PackLength($len);


  # spoon's smaller variable-length fnstenv encoder
  my $decoder;
  if($l->{'padLength'} <= 255) {
    # 23 bytes
    $decoder =
      "\xd9\xee".                         # fldz
      "\xd9\x74\x24\xf4".                 # fnstenv [esp - 12]
      "\x5b".                             # pop ebx
      "\x31\xc9".                         # xor ecx,ecx
      "\xb1". $l->{'lengthByte'} .        # mov cl, BYTE xorlen
      "\x81\x73\x17". $xorkey .           # xor_xor: xor DWORD [ebx + 24], xorkey
      "\x83\xeb\xfc".                     # sub ebx,-4
      "\xe2\xf4"                          # loop xor_xor
  }
  elsif($l->{'padLength'} <= 65535) {
    # 25 bytes
    $decoder =
      "\xd9\xee".                         # fldz
      "\xd9\x74\x24\xf4".                 # fnstenv [esp - 12]
      "\x5b".                             # pop ebx
      "\x31\xc9".                         # xor ecx,ecx
      "\x66\xb9". $l->{'lengthWord'} .    # mov cx, WORD xorlen
      "\x81\x73\x19". $xorkey .           # xor_xor: xor DWORD [ebx + 24], xorkey
      "\x83\xeb\xfc".                     # sub ebx,-4
      "\xe2\xf4"                          # loop xor_xor
  }
  return $decoder;
}

sub PackLength {
  my $len = shift;
  my $data = { 'small' => 0 };

  # Pad to a 4 byte boundary
  my $loopCounter = int(($len - 1) / 4) + 1;

  $data->{'padLength'} = $loopCounter;
  $data->{'negPadLength'} = -1 * $loopCounter;
  $data->{'length'} = pack('V', $data->{'padLength'});
  $data->{'negLength'} = pack('V', $data->{'negPadLength'});

  $data->{'negSmall'} = 1 if($data->{'negPadLength'} >= -128);
  $data->{'small'}    = 1 if($data->{'padLength'} <= 127);
  $data->{'lengthByte'} = substr($data->{'length'}, 0, 1);
  $data->{'negLengthByte'} = substr($data->{'negLength'}, 0, 1);
  $data->{'lengthWord'} = substr($data->{'length'}, 0, 2);
  $data->{'negLengthWord'} = substr($data->{'negLength'}, 0, 2);

  return($data);
}

sub XorDecoderWord {
    my ($arch, $xor, $len) = @_;
    if(! $len) { $len = 0x200 }

    # this xor decoder was written by hdm [at] metasploit.com
    if (lc($arch) eq "x86")
    {
        my $div = $len / 2;
        if ($len - (int($div) * 2) > 0) { $div++ }

        my $xorlen = pack("v", (0xffff - $div));
        my $xorkey = pack("v", $xor);

        my $decoder =
            "\xeb\x13".                     # jmp 8048095 <short_xor_end>
            # short_xor_beg:
            "\x5e".                         # pop %esi
            "\x31\xc9".                     # xor %ecx,%ecx
            "\x66\x81\xe9". $xorlen .       # sub $0xfff4,%cx
            # short_xor_xor:
            "\x66\x81\x36". $xorkey .       # xorw $0x1234,(%esi)
            "\x46".                         # inc %esi
            "\x46".                         # inc %esi
            "\xe2\xf7".                     # loop 804808a <short_xor_xor>
            "\xeb\x05".                     # jmp 804809a <short_xor_don>
            # short_xor_end:
            "\xe8\xe8\xff\xff\xff";         # call 8048082 <short_xor_beg>
        return $decoder;
    }
    return;
}

sub XorDecoderByte {
    my ($arch, $xor, $len) = @_;
    if(! $len) { $len = 0x200 }

    # this xor decoder was written by hdm [at] metasploit.com
    if (lc($arch) eq "x86")
    {
        $len = pack("v", 0xffff - $len);

        return
        "\xd9\xe1".                     # fabs
        "\xd9\x34\x24".                 # fnstenv (%esp,1)
        "\x5b".                         # pop %ebx
        "\x5b".                         # pop %ebx
        "\x5b".                         # pop %ebx
        "\x5b".                         # pop %ebx
        "\x80\xeb\xe7".                 # sub $0xe7,%ebx
        # short_xor_beg:
        "\x31\xc9".                     # xor %ecx,%ecx
        "\x66\x81\xe9$len".             # sub $len,%cx
        "\x80\x33". chr($xor).          # xorb $0x69,(%ebx)
        "\x43".                         # inc %ebx
        "\xe2\xfa";                     # loop 8048093 <short_xor_xor>
    }
    return;
}




#
# These routines take a buffer and xor encodes it with the given key
# value. The data is aligned to keysize blocks and padded with xor'd
# null values (to prevent pad ^ key problems)
#

sub XorDword {
    my ($xor, $buffer) = @_;
    my $res;
    my $c;

    for ($c = 0; $c < length($buffer); $c += 4)
    {
	    my $chunk = substr($buffer, $c);
        $chunk .= ("\x00" x (4 - length($chunk)));
	    $chunk  = unpack("V", $chunk) ^ $xor;
	    $res   .= pack("V", $chunk);
	}
    return $res;
}

sub XorWord {
    my ($xor, $buffer) = @_;
    my $res;
    my $c;
    for ($c = 0; $c < length($buffer); $c += 2)
    {
	    my $chunk = substr($buffer, $c);
        $chunk .= ("\x00" x (2 - length($chunk)));
	    $res   .= pack("v", unpack("v", $chunk) ^ $xor);
	}
    return $res;
}

sub XorByte {
    my ($xor, $buffer) = @_;
    my $res;

    foreach my $char (split(//, $buffer))
    {
        $res .= chr(ord($char) ^ $xor);
    }
    return $res;
}

# <joke>
# THIS ALGORITHM IS PATEND-PENDING BY JULIANO[at]COREST.COM AND USED UNDER LICENSE
# ATTEMPTS TO REVERSE ENGINEER THIS CODE WILL BE PROSECUTED UNDER THE DMCA
# </joke>

# I added some randomness, seems to work.  The idea is that you won't get the
# same key for the same payload like you would before. -spn

sub XorKeyScanDword {
  my @bytes = XorKeyScanDwordBytes(@_);
  return if(@bytes != 4);
  return(unpack('V', pack('C4', @bytes)));
}

sub XorKeyScanDwordBytes {
  my $data = shift;
  my $badChars = shift;

  my %badChars;
  my @dataFreq;
  my @badKeys;
  my @keys;

  my $i = 0;
  foreach my $c (split('', $data)) {
    $dataFreq[$i++ % 4]->{ord($c)}++;
  }

  foreach my $c (split('', $badChars)) {
    $badChars{ord($c)}++;
    for my $i (0 .. 3) {
      foreach my $d (keys(%{$dataFreq[$i]})) {
        $badKeys[$i]->{ord($c) ^ $d}++;
      }
    }
  }

LOOP:
  for my $d (0 .. 3) {
    my $r = int(rand(254));
    for my $c ($r .. $r + 254) {
      $c = ($c % 255) + 1;
      next if($badKeys[$d]->{$c} || $badChars{$c});
      $keys[$d] = $c;
      next LOOP;
    }
    # shit.
#    print "Damn on $d\n";
    return;
  }
  #print "SUCCESS! " . join('-', @keys) . "\n";
#  return(unpack('V', pack('C4', @keys)));
  return(@keys);
}

# Some sort of bad attempted at a feedback key scanner
# -spoon
sub KeyScanXorDwordFeedback {
  my $data = shift;
  my $badChars = shift;

  my %badChars;
  my @dataFreq;
  my @badKeys;
  my @keys;

  my $i = 0;
  foreach my $c (split('', $data)) {
    $dataFreq[$i++ % 4]->{ord($c)}++;
  }

  foreach my $c (split('', $badChars)) {
    $badChars{ord($c)}++;
    for my $i (0 .. 3) {
      foreach my $d (keys(%{$dataFreq[$i]})) {
        $badKeys[$i]->{ord($c) ^ $d}++;
      }
    }
  }

  my @r;
LOOP:
  for my $d (0 .. 3) {
    $r[$d] = int(rand(254));
    for my $c ($r[$d] .. $r[$d] + 254) {
      $c = ($c % 255) + 1;
      next if($badKeys[$d]->{$c} || $badChars{$c});
      $keys[$d] = $c;
      next LOOP;
    }
    # shit.
#    print "Damn on $d\n";
    return;
  }
#  print "1 SUCCESS! " . join('-', @keys) . "\n";

  while(1) {
    my $pos = XorDwordFeedbackCheck(unpack('V', pack('C4', @keys)), $data, $badChars);
    my $kindex = Pex::Text::BadCharIndex($badChars, pack('C4', @keys));
    last if($pos == -1 && $kindex == -1);
    $pos = $kindex if($pos == -1);
#    print "Bad at $pos\n";
    $pos = $pos % 4;
    my $stop = (($r[$pos] + 254) % 255) + 1;
#    print "Stop at $stop\n";
    return if($keys[$pos] == $stop);
    $keys[$pos]  = ($keys[$pos] % 254) + 1;
#    print "$pos -> " . $keys[$pos] . "\n";
  }

#  print "2 SUCCESS! " . join('-', @keys) . "\n";
  return(unpack('V', pack('C4', @keys)));
}

sub XorDwordFeedback {
  my ($xor, $buffer) = @_;
  my $res;

#  printf("New xor key 0x%08x $xor\n", $xor);

  for(my $c = 0; $c < length($buffer); $c += 4) {
    my $chunk = substr($buffer, $c, 4);
    my $spacing = 4 - length($chunk);
    $chunk .= "\x00" x $spacing;
    my $clean = unpack('V', $chunk);
    $chunk = $clean ^ $xor;
    $xor = DWordAdd($xor, $clean);
#    printf("New xor key 0x%08x $xor\n", $xor);
    $res .= substr(pack('V', $chunk), 0, 4 - $spacing);
  }
  return($res);
}

sub XorDwordFeedbackCheck {
  my $key = shift;
  my $data = shift;
  my $badChars = shift;
  return(Pex::Text::BadCharIndex($badChars, XorDwordFeedback($key, $data)));
}

sub DWordAdd {
  my $num1 = shift;
  my $num2 = shift;
  return(($num1 + $num2) % 4294967296);
}


1;
