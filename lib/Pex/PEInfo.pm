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

sub new {
    my ($class, $args) = @_;
    my $self = bless {}, $class;
    return $self->_Init($args);
}


sub _Init {
    my $self = shift;
    my $args = shift;
    
    $self->{'RAW'}         = "";
    $self->{'LastError'}   = "";
    $self->{'IMG_HDR'}     = { };
    $self->{'OPT_IMG_HDR'} = { };
    $self->{'RVA'}         = { };
    $self->{'SECTIONS'}    = { };
    $self->{'IMPORT'}      = { };
    $self->{'EXPORT'}      = { };
    
    $self->Debug(1);
    
    $self->LoadImage($args);
    return $self;
}

sub Debug {
    my $self = shift;
    if (@_) { $self->{'Debug'} = shift() }
    return $self->{'Debug'};
}

sub LastError {
    my $self = shift;
    if (@_) { $self->{'LastError'} = shift() }
    return $self->{'LastError'};
}

sub Raw {
    my $self = shift;
    return $self->{'RAW'};
}

sub ImageHeader {
    my $self = shift;
    my $name = shift;
    if (exists($self->{'IMG_HDR'}->{$name})) {
        return $self->{'IMG_HDR'}->{$name};
    }
    return;
}

sub ImageHeaders {
    my $self = shift;
    return keys( %{ $self->{'IMG_HDR'} } );
}

sub OptImageHeader {
    my $self = shift;
    my $name = shift;
    if (exists($self->{'OPT_IMG_HDR'}->{$name})) {
        return $self->{'OPT_IMG_HDR'}->{$name};
    }
    return;
}

sub OptImageHeaders {
    my $self = shift;
    return keys( %{ $self->{'OPT_IMG_HDR'} } );
}

sub Rva {
    my $self = shift;
    my $name = shift;
    if (exists($self->{'RVA'}->{$name})) {
        return $self->{'RVA'}->{$name};
    }
    return;
}

sub Rvas {
    my $self = shift;
    return keys( %{ $self->{'RVA'} } );
}

sub Section {
    my $self = shift;
    my $name = shift;
    if (exists($self->{'SECTIONS'}->{$name})) {
        return $self->{'SECTIONS'}->{$name};
    }
    return;
}

sub Sections {
    my $self = shift;
    return keys( %{ $self->{'SECTIONS'} } );
}

sub ImageBase {
    my $self = shift;
    if (@_) {
        $self->{'OPT_IMG_HDR'}->{'ImageBase'} = hex(shift());
        $self->_LoadImport();
    }
    return $self->{'OPT_IMG_HDR'}->{'ImageBase'};
}

sub LoadImage {
    my ($self, $fn) = @_;
    my $data;   
    local *X;
    
    if (! open(X, "<$fn")) {
        $self->LastError("Could not open file: $!");
        return;
    }
    
    while(<X>) { $data .= $_ }
    close(X);
    
    $self->{'RAW'} = $data;
    
    my $peo = $self->FindPEOffset(\$data);
    if (! $peo) {
        $self->LastError('Could not find PE header');
        return(undef);
    }
    
    my %IMAGE_HDR;
    my %OPT_IMAGE_HDR;
    my %RVA;
    my %SECTIONS;
    
    
    $IMAGE_HDR{'MachineID'}               = unpack('v', substr($data, $peo + 4));
    $IMAGE_HDR{'NumberOfSections'}        = unpack('v', substr($data, $peo + 6));
    $IMAGE_HDR{'TimeDateStamp'}           = unpack('V', substr($data, $peo + 8));
    $IMAGE_HDR{'PointerToSymbolTable'}    = unpack('V', substr($data, $peo + 12));
    $IMAGE_HDR{'NumberOfSymbols'}         = unpack('V', substr($data, $peo + 16));
    $IMAGE_HDR{'SizeOfOptionalHeader'}    = unpack('v', substr($data, $peo + 20));
    $IMAGE_HDR{'Characteristics'}         = unpack('v', substr($data, $peo + 22));

    if ($IMAGE_HDR{'SizeOfOptionalHeader'} > 0) {
        my $opthdr = substr($data, $peo + 24, $IMAGE_HDR{'SizeOfOptionalHeader'});

        $OPT_IMAGE_HDR{'Magic'}               = unpack('v', substr($opthdr, 0));
        $OPT_IMAGE_HDR{'MajorLinker'}         = unpack('C', substr($opthdr, 2));
        $OPT_IMAGE_HDR{'MinorLinker'}         = unpack('C', substr($opthdr, 3));
        $OPT_IMAGE_HDR{'SizeOfCode'}          = unpack('V', substr($opthdr, 4));
        $OPT_IMAGE_HDR{'SizeOfInitialized'}   = unpack('V', substr($opthdr, 8));
        $OPT_IMAGE_HDR{'SizeOfUninitialized'} = unpack('V', substr($opthdr, 12));

        $OPT_IMAGE_HDR{'EntryPoint'}          = unpack('V', substr($opthdr, 16));
        $OPT_IMAGE_HDR{'BaseOfCode'}          = unpack('V', substr($opthdr, 20));
        $OPT_IMAGE_HDR{'BaseOfData'}          = unpack('V', substr($opthdr, 24));

        $OPT_IMAGE_HDR{'ImageBase'}           = unpack('V', substr($opthdr, 28));
        $OPT_IMAGE_HDR{'SectionAlign'}        = unpack('V', substr($opthdr, 32));
        $OPT_IMAGE_HDR{'FileAlign'}           = unpack('V', substr($opthdr, 36));

        $OPT_IMAGE_HDR{'MajorOS'}             = unpack('v', substr($opthdr, 38));
        $OPT_IMAGE_HDR{'MinorOS'}             = unpack('v', substr($opthdr, 40));
        $OPT_IMAGE_HDR{'MajorImage'}          = unpack('v', substr($opthdr, 42));
        $OPT_IMAGE_HDR{'MinorImage'}          = unpack('v', substr($opthdr, 44));
        $OPT_IMAGE_HDR{'MajorSub'}            = unpack('v', substr($opthdr, 46));
        $OPT_IMAGE_HDR{'MinorSub'}            = unpack('v', substr($opthdr, 48));

        $OPT_IMAGE_HDR{'Reserved'}            = unpack('V', substr($opthdr, 52));
        $OPT_IMAGE_HDR{'SizeOfImage'}         = unpack('V', substr($opthdr, 56));
        $OPT_IMAGE_HDR{'SizeOfHeaders'}       = unpack('V', substr($opthdr, 60));
        $OPT_IMAGE_HDR{'Checksum'}            = unpack('V', substr($opthdr, 64));
        $OPT_IMAGE_HDR{'Subsystem'}           = unpack('v', substr($opthdr, 68));
        $OPT_IMAGE_HDR{'DllCharacteristics'}  = unpack('v', substr($opthdr, 70));
        $OPT_IMAGE_HDR{'SizeOfStackReserve'}  = unpack('V', substr($opthdr, 72));
        $OPT_IMAGE_HDR{'SizeOfStackCommit'}   = unpack('V', substr($opthdr, 76));
        $OPT_IMAGE_HDR{'SizeOfHeapReserve'}   = unpack('V', substr($opthdr, 80));
        $OPT_IMAGE_HDR{'SizeOfHeapCommit'}    = unpack('V', substr($opthdr, 84));
        $OPT_IMAGE_HDR{'LoaderFlags'}         = unpack('V', substr($opthdr, 88));
        $OPT_IMAGE_HDR{'NumberOfRvaAndSizes'} = unpack('V', substr($opthdr, 92));

        my @RVAMAP =
        (
            'export',
            'import',
            'resource',
            'exception',
            'certificate',
            'basereloc',
            'debug',
            'archspec',
            'globalptr',
            'tls',
            'load_config',
            'boundimport',
            'importaddress',
            'delayimport',
            'comruntime',
            'none'
        );

        # parse the rva data
        my $rva_data = substr($opthdr, 96, $OPT_IMAGE_HDR{'NumberOfRvaAndSizes'} * 8 );
        for (my $x = 0; $x < $OPT_IMAGE_HDR{'NumberOfRvaAndSizes'}; $x++)
        {
            if (! $RVAMAP[$x]) { $RVAMAP[$x] = "unknown_$x" }
            $RVA{ $RVAMAP[$x] } =
                        [
                            unpack('V', substr($rva_data, ($x * 8))),
                            unpack('V', substr($rva_data, ($x * 8) + 4)),
                        ];
        }
    }
    
    # parse the section headers
    my $sec_begn = $peo + 24 + $IMAGE_HDR{'SizeOfOptionalHeader'};
    my $sec_data = substr($data, $sec_begn);
    
    for (my $x = 0; $x < $IMAGE_HDR{'NumberOfSections'}; $x++)
    {
        my $sec_head = $sec_begn + ($x * 40);
        my $sec_name = substr($data, $sec_head, 8);
        $sec_name =~ s/\x00//g;

        $SECTIONS{$sec_name} =
                    [
                       unpack('V', substr($data, $sec_head +  8)),
                       unpack('V', substr($data, $sec_head +  12)),
                       unpack('V', substr($data, $sec_head +  16)),
                       unpack('V', substr($data, $sec_head +  20)), 
                    ];
                    
        # delta to virtual from file offset inside this section
        $SECTIONS{$sec_name}->[4] = $SECTIONS{$sec_name}->[1] - $SECTIONS{$sec_name}->[3];
    }   
    
    
    if ($self->Debug) {
        foreach (keys(%IMAGE_HDR)) { printf("%s\t0x%.8x\n", $_ , $IMAGE_HDR{$_}); }
        foreach (keys(%OPT_IMAGE_HDR)) { printf("%s\t0x%.8x\n", $_ , $OPT_IMAGE_HDR{$_}); }
        foreach (keys(%RVA)) { printf("%s\t0x%.8x [0x%.8x]\n", $_ , $RVA{$_}->[0], $RVA{$_}->[1] ); }
        foreach (keys(%SECTIONS)) 
        { 
            printf("%s\t0x%.8x\t0x%.8x\t0x%.8x\t0x%.8x\t0x%.8x\n",
                   $_ , $SECTIONS{$_}->[0], $SECTIONS{$_}->[1], $SECTIONS{$_}->[2], $SECTIONS{$_}->[3], $SECTIONS{$_}->[4]);
        }
    }
    
    $self->{'IMG_HDR'}      = \%IMAGE_HDR;
    $self->{'OPT_IMG_HDR'}  = \%OPT_IMAGE_HDR;
    $self->{'SECTIONS'}     = \%SECTIONS;
    $self->{'RVA'}          = \%RVA;
    
    $self->_LoadImport();
    $self->_LoadExport();

    return($self);    
}


sub _LoadImport {
    my $self = shift;
    my $data = $self->{'RAW'};
    my $import = $self->Rva('import');
    my $itable = {};
    
    return if ! $import;

    # Obtain the IMAGE_IMPORT_DESCRIPTOR array elements
    my $idata = substr($data, $self->_RV2O($import->[0]), $import->[1]);
   
    # The number of import modules  
    my $count = ($import->[1] / 20) - 1;

    for my $idx (0 .. ($count - 1)) {
        my @entry = unpack('VVVVV', substr($idata, $idx * 20, 20));
        
        if ($self->Debug) {
            print "\n[ IMPORT $idx ]\n";
            foreach (@entry) {
                printf("\t0x%.8x\n", $_);
            }
        }
        
        # all null struct can signify end of array
        last if ! $entry[0];
        
        my $oft_start_ref = $self->_RV2O($entry[0]);   # OrigFirstThunk
        my $dll_name_ref  = $self->_RV2O($entry[3]);   # DLL name
        my $rft_start_ref = $self->_RV2O($entry[4]);   # FirstThunk
        my $dll_name      = unpack('Z*', substr($data, $dll_name_ref, 256));
         
        my ($eidx, $erva) = (0, 1);       
        while ($erva != 0) {
            $erva = unpack('V',  substr($data, $oft_start_ref + (4 * $eidx), 4));
            next if ! $erva;
            
            my $entry_start_ref = $self->_RV2O($erva);
            
            my ($entry_name, $entry_hint_ord);
            if ($erva & 0x80000000) {
                my $ord = ($erva - 0x80000000);
                $entry_name     = "#$ord";
                $entry_hint_ord = $ord;
            }
            else {
                # Catch some really broken DLL's here
                if (! $entry_start_ref) {
                    print STDERR "PEInfo: invalid RVA $erva\n";
                    last;
                }

                $entry_name      = unpack('Z*', substr($data, $entry_start_ref+2, 256));
                $entry_hint_ord  = unpack('v', substr($data, $entry_start_ref, 2));
            }

            my $entry_iat_add   = $self->_O2V($rft_start_ref + (4 * $eidx));
            my $entry_iat_ref   = unpack('V', substr($data, $rft_start_ref + (4 * $eidx), 4));            
            
            if ($self->Debug) {
                printf("[ %s ]\t%.3d 0x%.8x 0x%.8x %.4d [0x%.8x|0x%.8x] %s\n",
                        lc($dll_name),
                        $eidx,
                        $oft_start_ref + (4 * $eidx),
                        $erva, 
                        $entry_hint_ord,
                        $entry_iat_add,
                        $entry_iat_ref,
                        $entry_name,
                        );
            }        

            $itable->{lc($dll_name)}->{$entry_name}->{'ord'} = $entry_hint_ord;
            $itable->{lc($dll_name)}->{$entry_name}->{'iat'} = $entry_iat_add;
            $itable->{lc($dll_name)}->{$entry_name}->{'iat_res'} = $entry_iat_ref;
            $eidx++;
        }    
    }
    $self->{'IMPORT'} = $itable;
}

sub _LoadExport {
    my $self = shift;
    my $data = $self->{'RAW'};
    my $export = $self->Rva('export');
    my $etable = {};

    return if ! $export;

    # Obtain the IMAGE_EXPORT_DIRECTORY structure
    my $edata  = substr($self->{'RAW'}, $self->_RV2O($export->[0]), $export->[1]);
    my @fields = unpack('V10', $edata);
    
    # fields[0] = Characteristics
    # fields[1] = TimeDateStamp
    # fields[2] = Major/Minor Version
    # fields[3] = Name RVA
    # fields[4] = Base
    # fields[5] = Number of Functions
    # fields[6] = Number of Names
    # fields[7] = Array of Functions
    # fields[8] = Array of Names
    # fields[9] = Array of Ordinals

    if ($self->Debug) {
        print "\n[ EXPORT ]\n";
        foreach (@fields) {
            printf("\t0x%.8x\n", $_);   
        }
        print "\n";
    }
    
    $etable->{'TimeDate'} = $fields[1];
    $etable->{'name'} = lc
    ( 
        unpack('Z*', substr($data, 
        $self->_RV2O($fields[3]), 256))
    );
    
    my $func_ptr = $self->_RV2O($fields[7]);
    my $name_ptr = $self->_RV2O($fields[8]);
    my $ord_ptr  = $self->_RV2O($fields[9]);

    # Build the ordinal -> address map first
    my @ord_table = ();
    for (my $idx = 0; $idx < $fields[5]; $idx++) {
        my $func_cur = unpack('V',  substr($data, $func_ptr + (4 * $idx), 4));
        $ord_table[$idx] = $func_cur;
    }

    # Scan the name -> ordinal map and match it up
    for (my $idx = 0; $idx < $fields[5]; $idx++) {

        # Pull the ordinal number for this name
        my $ord_cur  = unpack('v',  substr($data, $ord_ptr  + (2 * $idx), 2));

        # Match the ordinal to the function RVA
        my $func_cur = $ord_table[$ord_cur];

        # Make sure we didn't run out of names
        next if $idx > ($fields[6] - 1);

        # Read the function name from the names table                
        my $name_cur = unpack('V',  substr($data, $name_ptr + (4 * $idx), 4));
        my $name_str = unpack('Z*', substr($data, $self->_RV2O($name_cur), 512));

        # Add the ordinal base value
        $ord_cur += $fields[4];

        $etable->{'funcs'}->{$name_str}->{'ord'} = $ord_cur;
        $etable->{'funcs'}->{$name_str}->{'add'} = $func_cur + $self->ImageBase;
        $etable->{'ordinals'}->[$ord_cur]        = $name_str;
        
        if ($self->Debug) {    
            printf("0x%.8x %.4d %s\n", $func_cur, $ord_cur, $name_str);
        }
    }
    
    for (my $idx = 0; $idx < scalar(@ord_table); $idx++) {
        my $ord = $idx + $fields[4];
        my $ord_str = "#$ord";
        
        if (! exists($etable->{$ord_str})) {

            my $forwarder = unpack('Z*', substr($data, $self->_RV2O($ord_table[$idx]), 512));
            if ($forwarder =~ /^\w+\.\w+$/) {
                $ord_str = $forwarder;
                $etable->{'funcs'}->{$ord_str}->{'forwarder'}++;
            }
            
            $etable->{'ordinals'}->[$ord] = $ord_str;
            $etable->{'funcs'}->{$ord_str}->{'ord'} = $ord;
            $etable->{'funcs'}->{$ord_str}->{'add'} = $ord_table[$idx] + $self->ImageBase;

            if ($self->Debug) {    
                printf("0x%.8x %.4d %s\n", $ord_table[$idx], $ord, $ord_str);
            }
           
        }
    }
    

    $self->{'EXPORT'} = $etable;
}

sub FindPEOffset {
    my ($self, $data_ref) = @_;
    my $peo = unpack('V', substr(${$data_ref}, 0x3c, 4));
    if (substr(${$data_ref}, 0, 2) ne 'MZ'  || substr(${$data_ref}, $peo, 2) ne 'PE') { return } 
    return($peo);
}


sub OffsetToRVA {
    my ($self, $offset) = @_;
    return 0 if ! defined($offset);
    foreach (keys %{ $self->{'SECTIONS'} })  {
        my @section = @{ $self->{'SECTIONS'}->{$_} };
        if ( $offset >= $section[3] && $offset < ($section[2] + $section[3]) ) {
            return $offset + $section[4];
        }
    }   
}

sub RVAToOffset {
    my ($self, $virtual) = @_;
    return 0 if ! defined($virtual);
    foreach (keys %{ $self->{'SECTIONS'} }) {
        my @section = @{ $self->{'SECTIONS'}->{$_} };
        if ($virtual >= $section[1] && $virtual <= ($section[0] + $section[1])) {
            return $virtual - $section[4];
        }
    }
}

sub OffsetToVirtual {
    my ($self, $offset) = @_;
    return $self->OffsetToRVA($offset) + $self->{'OPT_IMG_HDR'}->{'ImageBase'};
}

sub VirtualToOffset {
    my ($self, $virtual) = @_;
    $virtual -= $self->{'OPT_IMG_HDR'}->{'ImageBase'};
    return $self->RVAToOffset($virtual);
}

sub _V2O {
    my $self = shift;
    return $self->VirtualToOffset(@_);
}

sub _RV2O {
    my $self = shift;
    return $self->RVAToOffset(@_);
}

sub _O2V {
    my $self = shift;
    return $self->OffsetToVirtual(@_);
}

sub _O2RV {
    my $self = shift;
    return $self->OffsetToRVA(@_);
}

1;
