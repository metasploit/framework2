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
    $self->{'RESOURCE'}    = { };
    $self->{'VERSION'}     = { };
    
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

sub Imports {
    my $self = shift;
    return $self->{'IMPORT'};
}

sub Import {
    my $self = shift;
    my $name = shift;
    return {} if ! exists($self->{'IMPORT'}->{$name});
    return $self->{'IMPORT'}->{$name};
}

sub IAT {
    my $self = shift;
    my $func = shift;
    
    foreach my $dll (keys(%{ $self->{'IMPORT'} })) {
        foreach my $proc (keys(%{ $self->{'IMPORT'}->{$dll} })) {
            if (lc($func) eq lc($func)) {
                return $self->{'IMPORT'}->{$dll}->{$proc}->{'iat_res'};
            }
        }
    }
}

sub Exports {
    my $self = shift;
    return $self->{'EXPORT'};
}

sub ExportAddress {
    my $self = shift;
    my $name = shift;
    return if ! exists($self->{'EXPORT'}->{'funcs'}->{$name});
    return $self->{'EXPORT'}->{'funcs'}->{$name}->{'add'};
}

sub ExportOrdinal {
    my $self = shift;
    my $name = shift;
    return if ! exists($self->{'EXPORT'}->{'funcs'}->{$name});
    return $self->{'EXPORT'}->{'funcs'}->{$name}->{'ord'};
}

sub ExportOrdinalLookup {
    my $self = shift;
    my $ord  = shift;
    return if ! defined($self->{'EXPORT'}->{'ordinals'}->[$ord]);
    return $self->{'EXPORT'}->{'ordinals'}->[$ord];
}

sub Resources {
    my $self = shift;
    return $self->{'RESOURCE'};
}

sub VersionStrings {
    my $self = shift;
    return $self->{'VERSION'};
}

sub VersionString {
    my $self = shift;
    my $name = shift;
    return if ! exists($self->{'VERSION'}->{$name});
    return $self->{'VERSION'}->{$name};
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
    $self->_LoadResources();
    $self->_LoadVersionData();
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

            my $entry_iat_add  = $self->_O2V($rft_start_ref + (4 * $eidx));
            my $entry_iat_ref  = unpack('V', substr($data, $rft_start_ref + (4 * $eidx), 4));            
            
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

            # Process forwarders
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

sub _LoadResources {
    my $self = shift;
    my $resource = $self->Rva('resource');
    my $rdata  = substr($self->{'RAW'}, $self->_RV2O($resource->[0]), $resource->[1]);
    my $rtable = {};
    
    # Recursive happy fun time!  
    $self->_ParseResourceDirectory($rtable, $rdata, 0, 0x80000000, "0");
    $self->{'RESOURCE'} = $rtable;
}

sub _ParseResourceName {
    my $self = shift;
    my ($rdata, $rname) = @_;    
    if ($rname & 0x80000000) {
        $rname -= 0x80000000;
        my $unistr = substr($rdata, $rname+2, 2 * unpack('v', substr($rdata, $rname, 2)));
        my $ansstr = $self->_UNI2ANSI($unistr);
        return $ansstr;
    } else { return "$rname" }
}

sub _ParseResourceEntry { 
    my $self = shift;
    my ($rdata, $rname, $rvalue) = @_;
    my $res = { };
  
    my ($drva, $dsize, $dcode) = unpack('V3', substr($rdata, $rvalue, 12));
    my $entry = substr($self->{'RAW'}, $self->_RV2O($drva), $dsize);
    
    $res->{'Name'} = $self->_ParseResourceName($rdata, $rname);
    $res->{'Data'} = $entry;
    $res->{'Code'} = $dcode;
    $res->{'RVA'}  = $drva;
    return $res;
}

sub _ParseResourceDirectory {
    my $self = shift;
    my ($rtable, $rdata, $rname, $rvalue, $cindex) = @_;
    
    # Sanity check to prevent infinite loops ]:|
    return if length($cindex) > 65535;

    # Convert the name to a string value
    $rname = $self->_ParseResourceName($rdata, $rname);
    
    # Ghettofabulous depth counter
    my $depth = $cindex =~ tr/\//\//;

    if ($depth == 1) {
        $cindex = "/".$self->_ResID2Name($rname);
    }
    
    # Remove the high bit from the offset value
    $rvalue -= 0x80000000;
    
    # Read the directory header
    my @rfields = unpack('VVv4', substr($rdata, $rvalue, 16));
    
    $rtable->{'Dirs'}->{$cindex}->{'Name'} = $rname;
    $rtable->{'Dirs'}->{$cindex}->{'Characteristics'} = $rfields[0];
    $rtable->{'Dirs'}->{$cindex}->{'TimeDate'} = $rfields[1];
    $rtable->{'Dirs'}->{$cindex}->{'Version'} = $rfields[2].$rfields[3];
    $rtable->{'Dirs'}->{$cindex}->{'Entries'} = $rfields[4]+$rfields[5];

    if ($self->Debug) {
        print "$rname\tDIR\t$cindex (".$rtable->{'Dirs'}->{$cindex}->{'DirType'} .")\n";
    }
    
    for my $rindex (0 .. ($rfields[4] + $rfields[5] - 1)) {
        my ($rname, $rvalue) = unpack('VV', substr($rdata, $rvalue + 16 + ($rindex * 8), 8));
        my $path = $cindex."/".$rindex;

        if ($rvalue & 0x80000000) {
            # Recursively parse the subdirectory
            $self->_ParseResourceDirectory($rtable, $rdata, $rname, $rvalue, $path);
        }
        else {
            # Place resource entry into the hash
            $rtable->{'Entries'}->{$path} = $self->_ParseResourceEntry($rdata, $rname, $rvalue);
            
            # Map into the types table as well
            my ($base) = $cindex =~ m/^\/([^\/]+)/;
            $rtable->{'Types'}->{$base}->{$path} = $rtable->{'Entries'}->{$path};
            
            if ($self->Debug) {
                print $rtable->{'Entries'}->{$path}->{'Name'}."\tENT\t$path\t($base)\n";
            }
        }
    }
}


sub _ResID2Name {
    my $self = shift;
    my $tid  = shift;
    
    my %tmap =
    (
        '1'      => 'CURSOR',
        '2'      => 'BITMAP',
        '3'      => 'ICON',
        '4'      => 'MENU',
        '5'      => 'DIALOG',
        '6'      => 'STRING',
        '7'      => 'FONTDIR',
        '8'      => 'FONT',
        '9',     => 'ACCELERATORS',
        '10'     => 'RCDATA',
        '11'     => 'MESSAGETABLE',
        '12'     => 'GROUP_CURSOR',
        '14'     => 'GROUP_ICON',
        '16'     => 'VERSION',
        '32767'  => 'ERROR',
        '8192'   => 'NEWRESOURCE',
        '8194'   => 'NEWBITMAP',
        '8196'   => 'NEWMENU',
        '8197'   => 'NEWDIALOG',
        
    );
    
    return ($tid) if $tid !~ /^\d/;
    return $tmap{$tid} || $tid;
}

sub _LoadVersionData {
    my $self = shift;
    my $resource = $self->Rva('resource');

    my $rdata = substr($self->{'RAW'}, $self->_RV2O($resource->[0]), $resource->[1]);
    my $vdata = $self->{'RESOURCE'}->{'Types'}->{'VERSION'};
    return if ! $vdata;

    my ($versionFile, $versionProd);
    
    # XXX - Only read first section right now
    my $vblock = $vdata->{'/VERSION/0/0'}->{'Data'};
    my $vblock_rva = $vdata->{'/VERSION/0/0'}->{'RVA'};
    
    my ($vinf_wlen, $vinf_vlen, $vinf_type) = unpack('v3', $vblock);
    my $vinf_wkey = $self->_UNI2ANSI(substr($vblock, 6));
    my $vinf_xpad = (length($vinf_wkey) * 2) + 2 + 6;
    
    # Pad it up to the VS_FIXEDFILEINFO structure
    while (($vblock_rva + $vinf_xpad) % 4 != 0) {
        $vinf_xpad++;
    }
    
    if ($vinf_vlen != 0) {
        my $vfixed_ptr = index($vblock, pack('V', 0xfeef04bd));
        
        if ($vfixed_ptr != $vinf_xpad) {
            print STDERR "PEInfo::_LoadVersionData: mismatch of VS_FIXEDFILEINFO start offsets\n";
        }
        
        my @vfixed = unpack('VVv8V*', substr($vblock, $vfixed_ptr, $vinf_vlen));   
        $versionFile = join(".", ( $vfixed[3], $vfixed[2], $vfixed[5], $vfixed[4]));
        $versionProd = join(".", ( $vfixed[7], $vfixed[6], $vfixed[9], $vfixed[8]));
    }
    
    # Add the length of the VS_FIXEDFILEINFO structure
    $vinf_xpad += $vinf_vlen;
    
    # Pad it up to the first StringFileInfo structure
    while (($vblock_rva + $vinf_xpad) % 4 != 0) {
        $vinf_xpad++;
    }
    
    # Read and parse the StringFileInfo structure
    my ($sinf_wlen) = unpack('v', substr($vblock, $vinf_xpad, 2));
    my $sinf_wkey = $self->_UNI2ANSI(substr($vblock, $vinf_xpad + 6, 256));
    my $sinf_xpad = $vinf_xpad + (length($sinf_wkey) * 2) + 2 + 6;
    
    if ($sinf_wkey ne 'StringFileInfo') {
        print STDERR "PEInfo::_LoadVersionData: StringFileInfo not found first in VERSION_INFO\n";
        print STDERR "DATA: ".unpack("H*", substr($vblock, $vinf_xpad + 6, 64))."\n";
    }
    
    # Pad it up to the StringArray structure
    while (($vblock_rva + $sinf_xpad) % 4 != 0) {
        $sinf_xpad++;
    }

    # Determine the maximum byte length of the array
    my $sinf_size = $sinf_wlen - ($sinf_xpad - $vinf_xpad );
    
    my $sfi = $self->_ParseStringTableArray($vblock, $vblock_rva, $sinf_xpad, $sinf_size);
    if ($versionFile) {
        $sfi->{'FixedFileVersion'} = $versionFile;
        $sfi->{'FixedProdVersion'} = $versionProd;
    }
    
    $self->{'VERSION'} = $sfi;
    
    # Point this to the next structure (VarFileInfo)
    $vinf_xpad += $sinf_wlen;
    
    # XXX VarFileInfo not implemented yet
}

sub _ParseStringTableArray {
    my $self = shift;
    my ($vblock, $vblock_rva, $sinf_xpad, $sinf_size) = @_;
    my $sinf_xptr = $sinf_xpad;
    my $res = { };
    
    while ($sinf_xptr < $sinf_xpad + $sinf_size) {
            
        my ($ainf_wlen) = unpack('v', substr($vblock, $sinf_xptr, 2));
        my $ainf_wkey = $self->_UNI2ANSI(substr($vblock, $sinf_xptr + 6, 256));
        my $ainf_xpad = $sinf_xptr + (length($ainf_wkey) * 2) + 2 + 6;
        
        # Pad it up to the String structure array
        while (($vblock_rva + $ainf_xpad) % 4 != 0) {
            $ainf_xpad++;
        }
        
        # Create a stub hash for strings in this language
        $res->{$ainf_wlen} = {};
        
        # This is getting repetitive...
        my $ainf_size = $ainf_wlen - ($ainf_xpad - $sinf_xpad);
        my $ainf_xptr = $ainf_xpad;
        
        while ($ainf_xptr < $ainf_xpad + $ainf_size) {

            my ($binf_wlen, $binf_vlen) = unpack('v2', substr($vblock, $ainf_xptr, 4));
            my $binf_wkey = $self->_UNI2ANSI(substr($vblock, $ainf_xptr + 6, 256));
            my $binf_xpad = $ainf_xptr + (length($binf_wkey) * 2) + 2 + 6;

            # Pad it up to the actual String structure
            while (($vblock_rva + $binf_xpad) % 4 != 0) {
                $binf_xpad++;
            }
            
            # Store the unicode string value...
            $res->{$ainf_wlen}->{$binf_wkey} = $self->_UNI2ANSI(substr($vblock, $binf_xpad, 256));        

            # Push the ptr to the next structure
            $ainf_xptr += $binf_wlen;
            
            # Align the ptr if needed
            while (($ainf_xptr + $vblock_rva) % 4 != 0) {
                $ainf_xptr++;
            }
        }
        
        # Push the ptr to the next structure
        $sinf_xptr += $ainf_wlen;   
        
        # Align the ptr if needed
        while (($sinf_xptr + $vblock_rva) % 4 != 0) {
            $sinf_xptr++;
        }
    }
    return $res;
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

sub _UNI2ANSI {
    my $self = shift;
    my $data = shift;
    ($data) = split(/\x00\x00/, $data);
    $data =~ s/\x00//g;
    return $data;
}

1;
