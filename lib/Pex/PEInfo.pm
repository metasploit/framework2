#!/usr/bin/perl
###############

##
#         Name: PEInfo.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##


package Pex::PEInfo;
use strict;

my $RAW;
my $LastErrorVal;
my %IMAGE_HDR;
my %OPT_IMAGE_HDR;
my %RVA;
my %SECTIONS;



sub new {
    my ($class, $args) = @_;
    my $selfect = bless {}, $class;
    return($selfect->LoadImage($args));
}

sub LastError {
    my $selfect = shift;
    if (@_) { $LastErrorVal = shift }
    return ($LastErrorVal);
}

sub Raw {
    my $selfect = shift;
    return $RAW;
}

sub ImageHeader {
    my $selfect = shift;
    my $name = shift;
    if (exists($IMAGE_HDR{$name}))
    {
        return($IMAGE_HDR{$name});
    }
    return undef;
}

sub ImageHeaders {
    my $selfect = shift;
    return keys(%IMAGE_HDR);
}

sub OptImageHeader {
    my $selfect = shift;
    my $name = shift;
    if (exists($OPT_IMAGE_HDR{$name}))
    {
        return($OPT_IMAGE_HDR{$name});
    }
    return undef;
}

sub OptImageHeaders {
    my $selfect = shift;
    return keys(%OPT_IMAGE_HDR);
}

sub Rva {
    my $selfect = shift;
    my $name = shift;
    if (exists($RVA{$name}))
    {
        return($RVA{$name});
    }
    return undef;
}

sub Rvas {
    my $selfect = shift;
    return keys(%RVA);
}

sub Section {
    my $selfect = shift;
    my $name = shift;
    if (exists($SECTIONS{$name}))
    {
        return($SECTIONS{$name});
    }
    return undef;
}

sub Sections {
    my $selfect = shift;
    return keys(%SECTIONS);
}

sub ImageBase {
    my $selfect = shift;
    $OPT_IMAGE_HDR{"ImageBase"} = hex(shift()) if @_;
    return $OPT_IMAGE_HDR{"ImageBase"};
}

sub LoadImage {
    my ($selfect, $fn) = @_;
    my $data;   
    local *X;
    
    if (! open(X, "<$fn"))
    {
        $selfect->LastError("Could not open file: $!");
        return(undef);
    }
    
    while(<X>) { $data .= $_ }
    close(X);
    
    $RAW = $data;
    
    my $peo = $selfect->FindPEOffset(\$data);
    if (! $peo)
    {
        $selfect->LastError("Could not find PE header");
        return(undef);
    }
    
    $IMAGE_HDR{"MachineID"}               = unpack("S", substr($data, $peo + 4));
    $IMAGE_HDR{"NumberOfSections"}        = unpack("S", substr($data, $peo + 6));
    $IMAGE_HDR{"TimeDateStamp"}           = unpack("V", substr($data, $peo + 8));
    $IMAGE_HDR{"PointerToSymbolTable"}    = unpack("V", substr($data, $peo + 12));
    $IMAGE_HDR{"NumberOfSymbols"}         = unpack("V", substr($data, $peo + 16));
    $IMAGE_HDR{"SizeOfOptionalHeader"}    = unpack("S", substr($data, $peo + 20));
    $IMAGE_HDR{"Characteristics"}         = unpack("S", substr($data, $peo + 22));

    if ($IMAGE_HDR{"SizeOfOptionalHeader"} > 0)
    {
        my $opthdr = substr($data, $peo + 24, $IMAGE_HDR{"SizeOfOptionalHeader"});

        $OPT_IMAGE_HDR{"Magic"}               = unpack("S", substr($opthdr, 0));
        $OPT_IMAGE_HDR{"MajorLinker"}         = unpack("C", substr($opthdr, 2));
        $OPT_IMAGE_HDR{"MinorLinker"}         = unpack("C", substr($opthdr, 3));
        $OPT_IMAGE_HDR{"SizeOfCode"}          = unpack("V", substr($opthdr, 4));
        $OPT_IMAGE_HDR{"SizeOfInitialized"}   = unpack("V", substr($opthdr, 8));
        $OPT_IMAGE_HDR{"SizeOfUninitialized"} = unpack("V", substr($opthdr, 12));

        $OPT_IMAGE_HDR{"EntryPoint"}          = unpack("V", substr($opthdr, 16));
        $OPT_IMAGE_HDR{"BaseOfCode"}          = unpack("V", substr($opthdr, 20));
        $OPT_IMAGE_HDR{"BaseOfData"}          = unpack("V", substr($opthdr, 24));

        $OPT_IMAGE_HDR{"ImageBase"}           = unpack("V", substr($opthdr, 28));
        $OPT_IMAGE_HDR{"SectionAlign"}        = unpack("V", substr($opthdr, 32));
        $OPT_IMAGE_HDR{"FileAlign"}           = unpack("V", substr($opthdr, 36));

        $OPT_IMAGE_HDR{"MajorOS"}             = unpack("S", substr($opthdr, 38));
        $OPT_IMAGE_HDR{"MinorOS"}             = unpack("S", substr($opthdr, 40));
        $OPT_IMAGE_HDR{"MajorImage"}          = unpack("S", substr($opthdr, 42));
        $OPT_IMAGE_HDR{"MinorImage"}          = unpack("S", substr($opthdr, 44));
        $OPT_IMAGE_HDR{"MajorSub"}            = unpack("S", substr($opthdr, 46));
        $OPT_IMAGE_HDR{"MinorSub"}            = unpack("S", substr($opthdr, 48));

        $OPT_IMAGE_HDR{"Reserved"}            = unpack("V", substr($opthdr, 52));
        $OPT_IMAGE_HDR{"SizeOfImage"}         = unpack("V", substr($opthdr, 56));
        $OPT_IMAGE_HDR{"SizeOfHeaders"}       = unpack("V", substr($opthdr, 60));
        $OPT_IMAGE_HDR{"Checksum"}            = unpack("V", substr($opthdr, 64));
        $OPT_IMAGE_HDR{"Subsystem"}           = unpack("S", substr($opthdr, 68));
        $OPT_IMAGE_HDR{"DllCharacteristics"}  = unpack("S", substr($opthdr, 70));
        $OPT_IMAGE_HDR{"SizeOfStackReserve"}  = unpack("V", substr($opthdr, 72));
        $OPT_IMAGE_HDR{"SizeOfStackCommit"}   = unpack("V", substr($opthdr, 76));
        $OPT_IMAGE_HDR{"SizeOfHeapReserve"}   = unpack("V", substr($opthdr, 80));
        $OPT_IMAGE_HDR{"SizeOfHeapCommit"}    = unpack("V", substr($opthdr, 84));
        $OPT_IMAGE_HDR{"LoaderFlags"}         = unpack("V", substr($opthdr, 88));
        $OPT_IMAGE_HDR{"NumberOfRvaAndSizes"} = unpack("V", substr($opthdr, 92));

        my @RVAMAP =
        (
            "export",
            "import",
            "resource",
            "exception",
            "certificate",
            "basereloc",
            "debug",
            "archspec",
            "globalptr",
            "tls",
            "load_config",
            "boundimport",
            "importaddress",
            "delayimport",
            "comruntime",
            "none"
        );

        # parse the rva data
        my $rva_data = substr($opthdr, 96, $OPT_IMAGE_HDR{"NumberOfRvaAndSizes"} * 8 );
        for (my $x = 0; $x < $OPT_IMAGE_HDR{"NumberOfRvaAndSizes"}; $x++)
        {
            if (! $RVAMAP[$x]) { $RVAMAP[$x] = "unknown_$x" }
            $RVA{ $RVAMAP[$x] } =
                        [
                            unpack("V", substr($rva_data, ($x * 8))),
                            unpack("V", substr($rva_data, ($x * 8) + 4)),
                        ];
        }
    }
    
    # parse the section headers
    my $sec_begn = $peo + 24 + $IMAGE_HDR{"SizeOfOptionalHeader"};
    my $sec_data = substr($data, $sec_begn);
    
    for (my $x = 0; $x < $IMAGE_HDR{"NumberOfSections"}; $x++)
    {
        my $sec_head = $sec_begn + ($x * 40);
        my $sec_name = substr($data, $sec_head, 8);
        $sec_name =~ s/\x00//g;

        $SECTIONS{$sec_name} =
                    [
                       unpack("V", substr($data, $sec_head +  8)),
                       unpack("V", substr($data, $sec_head +  12)),
                       unpack("V", substr($data, $sec_head +  16)),
                       unpack("V", substr($data, $sec_head +  20)), 
                    ];
                    
        # delta to virtual from file offset inside this section
        $SECTIONS{$sec_name}->[4] = $SECTIONS{$sec_name}->[1] - $SECTIONS{$sec_name}->[3];
    }   
    
    #foreach (keys(%IMAGE_HDR)) { printf("%s\t0x%.8x\n", $_ , $IMAGE_HDR{$_}); }
    #foreach (keys(%OPT_IMAGE_HDR)) { printf("%s\t0x%.8x\n", $_ , $OPT_IMAGE_HDR{$_}); }
    #foreach (keys(%RVA)) { printf("%s\t0x%.8x [0x%.8x]\n", $_ , $RVA{$_}->[0], $RVA{$_}->[1] ); }
    #foreach (keys(%SECTIONS)) 
    #{ 
    #    printf("%s\t0x%.8x\t0x%.8x\t0x%.8x\t0x%.8x\t0x%.8x\n",
    #           $_ , $SECTIONS{$_}->[0], $SECTIONS{$_}->[1], $SECTIONS{$_}->[2], $SECTIONS{$_}->[3], $SECTIONS{$_}->[4]);
    #}
    
    return($selfect);    
}

sub OffsetToVirtual {
    my ($selfect, $offset) = @_;

    # if this image has no optional header and defined image base,
    # just return zero since we can't calculate the virtual
    if (! $OPT_IMAGE_HDR{"ImageBase"})
    {
        return(0);
    }

    foreach (keys(%SECTIONS)) 
    {
        if ($offset >= $SECTIONS{$_}->[3] && $offset < ($SECTIONS{$_}->[3] + $SECTIONS{$_}->[2]))
        {
            return($OPT_IMAGE_HDR{"ImageBase"} + $offset + $SECTIONS{$_}->[4]);
        }
    }   
        
    # not in any given section, return the offset + ImageBase    
    return($OPT_IMAGE_HDR{"ImageBase"} + $offset);
}

sub VirtualToOffset {
    my ($selfect, $virtual) = @_;
    if (! $virtual) { return(0) }
    
    foreach (keys(%SECTIONS)) 
    {
       if ($virtual > $SECTIONS{$_}->[1] && $virtual < ($SECTIONS{$_}->[0] + $SECTIONS{$_}->[1]))
       {
            return $virtual - $SECTIONS{$_}->[4];
       }
    }   
    return(0);
}

sub FindPEOffset {
    my ($selfect, $data_ref) = @_;
    my $peo = unpack("V", substr(${$data_ref}, 0x3c, 4));
    if (substr(${$data_ref}, 0, 2) ne "MZ"  || substr(${$data_ref}, $peo, 2) ne "PE") { return undef } 
    return($peo);
}

1;
