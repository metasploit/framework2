###############
#
#         Name: NDR.pm
#       Author: Brian Caswell <bmc@shmoo.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

=head1 NAME

Pex::NDR - An API for encoding data for DCE/RPC (Network Data Representation)

As XDR is for ONC/RPC, NDR is for DCE/RPC

=cut

package Pex::NDR;
use warnings;
use strict;
use Pex::Text;

=head1 FUNCTIONS

=head2 DwordAlign($size)

Provide padding to align data of length ($size) to the 32bit boundary.

=cut

sub DwordAlign {
    my ($length) = @_;
    return Pex::Text::RandomData( ( 4 - ( $length & 3 ) ) & 3 );
}

=head2 Long($value, [$value, $value])

Encode a 4 byte long

Use to encode:

    long element_1;

=cut

sub Long {
    return pack( 'V*', @_ );
}

=head2 Short($value, [$value, $value])

encode a 2 byte short

Use to encode:

    short element_1;

=cut

sub Short {
    return pack( 'v*', @_ );
}

=head2 Byte($value, [$value, $value])

encode a single byte.

Use to encode:

    byte element_1;

=cut

sub Byte {
    return pack( 'C*', @_ );
}

=head2 Unique($value)

Wrap the provided data structure in a unique 4 byte number.  This is useful for encoding stuctures such as :
    
    [unique] long element_1;

Use as:

    Pex::NDR::Unique(Pex::NDR::Long($element_1));

=cut

{
    my $_unique;

    sub Unique {
        my ($string) = @_;
        $_unique++;

        $string = Long($_unique) . $string;
        return $string;
    }
}

=head2 UnicodeConformantVaryingString($string)

Encode a string in wide character format, including converting it the string to Unicode.

Use to encode the following structure:
    
    w_char *element_1;

=head3 NOTE:

This function handles null terminators and padding!

=cut 

sub UnicodeConformantVaryingString {
    my ($string) = @_;

    $string = $string . "\x00";
    my $len = length($string);

    $string = Long( $len, 0, $len ) . Unicode($string);

    my $align = DwordAlign( $len * 2 );
    if ($align) {
        $string .= $align;
    }
    return $string;
}

=head2 UnicodeConformantVaryingStringPreBuilt($string)

Encode a wide character string in wide character format.

Use to encode the following structure, where the provided data is already encoded in Unicode:
    
    w_char *element_1;

=head3 NOTE:

This function does not provide null terminators, but it does provide padding.  Provide the null terminators (since they are almost ALWAYS required)!

=cut 

sub UnicodeConformantVaryingStringPreBuilt {
    my ($string) = @_;

    # if the prebuilt string has an odd length, thats fucked.  pad it with nulls
    $string .= "\x00" if ( length($string) % 2 );

    my $len = length($string) / 2;

    $string = Long( $len, 0, $len ) . $string;

    my $align = DwordAlign( length($string) );

    if ($align) {
        $string .= $align;
    }
    return $string;
}

=head2 UniConformantArray($data)

This implements:

    [in]  char  element_1

If there is a sizeis, such as:
    
    [size_is(element_2)] [in]  char  element_1,
    long element_2,

You have to provide size value as well (eg: element1).  So, for the above size_is example use:

    UniConformantArray($data) . Long(length($data))

=cut

sub UniConformantArray {
    my ($data) = @_;

    my $string = Long( length($data) ) . $data;

    my $align = DwordAlign( length($string) );

    if ($align) {
        $string .= $align;
    }
    return $string;
}

=head2 UniConformantByteArray($data)

A cheap hack to implement the common format of:

    long element_1,
    [size_is(element_1)] [in]  char  element_2,

Instead of:

    Long(length($data)) . UniConformantArray($data) as in the above

Use:
    
    UniConformantByteArray($data)

=cut

sub UniConformantByteArray {
    my ($data) = @_;

    my $string = Long( length($data), length($data) ) . $data;

    my $align = DwordAlign( length($string) );

    if ($align) {
        $string .= $align;
    }
    return $string;
}

=head2 Unicode($data)

Encode an ASCII string as UTF8

=cut

sub Unicode {
    return pack( 'v*', unpack( 'C*', shift() ) );
}

=head2 test

This isn't ment to be called, unless of course you want to test Pex::NDR!  Typically, this is called automagically via:

perl -Ilib lib/Pex/NDR.pm

=cut

sub test {
    require Test::More;
    import Test::More;
    plan( tests => 20 );

    is( Unicode("A"), "A\x00",            'Unicode' );
    is( Unicode(''),  '',                 'Unicode (null string)' );
    is( Long(10),     "\x0a\x00\x00\x00", 'Long' );
    is( Short(10),    "\x0a\x00",         'Short' );
    is( Byte(10),     "\x0a",             'Byte' );

    is( Long( 1, 2 ), "\x01\x00\x00\x00\x02\x00\x00\x00", 'Long Multiple' );
    is( Short( 1, 2 ), "\x01\x00\x02\x00", 'Short Multiple' );
    is( Byte( 10, 11 ), "\x0a\x0b", 'Byte Multiple' );

    is( length( DwordAlign(1) ), 3,     'DwordAlign (1)' );
    is( length( DwordAlign(3) ), 1,     'DwordAlign (3)' );
    is( DwordAlign(12),          undef, 'DwordAlign (12)' );

    is(
        length( UniConformantArray('aaaaa') ),
        4 + 5 + 3,
        'UniConformantArray(aaaaa) length'
    );
    is( substr( UniConformantArray('aaaaa'), 0, 9 ),
        "\x05\x00\x00\x00aaaaa", 'UniConformantArray(aaaaa) data' );

    is(
        length( UnicodeConformantVaryingString('abcde') ),
        4 + 4 + 4 + 12,
        'UnicodeConformantVaryingString(abcde) length'
    );
    is(
        substr( UnicodeConformantVaryingString('abcde'), 0, 12 + 12 ),
"\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00a\x00b\x00c\x00d\x00e\x00\x00\x00",
        'UnicodeConformantVaryingString(abcde) data'
    );

    is(
        length( UnicodeConformantVaryingStringPreBuilt('abcde') ),
        4 + 4 + 4 + 6 + 2,
        'UnicodeConformantVaryingStringPreBuilt(abcde) length'
    );
    is(
        substr( UnicodeConformantVaryingStringPreBuilt('abcde'), 0, 12 + 6 ),
        "\x03\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00abcde\x00",
        'UnicodeConformantVaryingStringPreBuilt(abcde) data'
    );

    # use BMC;
    # warn BMC::bin2hex(UniqueUnicodeConformantVaryingString('abcde'));
    is(
        length( Unique( UnicodeConformantVaryingString('abcde') ) ),
        4 + ( 4 * 3 ) + ( ( 5 + 1 ) * 2 ),
        'Unique(UnicodeConformantVaryingString(aaaaa)) length'
    );
    is(
        substr(
            Unique( UnicodeConformantVaryingString('abcde') ),
            4, 4 + ( 4 * 3 ) + ( ( 5 + 1 ) * 2 )
        ),
"\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00a\x00b\x00c\x00d\x00e\x00\x00\x00",
        'Unique(UnicodeConformantVaryingString(aaaaa)) data'
    );

    isnt(
        substr( Unique('a'), 0, 4 ),
        substr( Unique('a'), 0, 4 ),
        'Unique of the same string have different IDs'
    );
}

if ( !( caller() )[0] ) {
    Pex::NDR::test();
}

=head2  Common IDL structures that are not handled here

=head3 UUID

typedef struct {
    long element_1;
    short element_2;
    short element_3;
    [size_is(8)] byte *element_4;
} TYPE_1;

Use:

    Pex::DCERPC::UUID_to_Bin('00000000-0000-0000-0000-000000000000');

=head2 AUTHOR

Brian Caswell <bmc@shmoo.com>

=cut

'I wonder if anyone ever bothers to read this...';
