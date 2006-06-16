
###############

##
#         Name: ELFInfo.pm
#       Author: Richard Johnson <rjohnson [at] uninformed.org>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##


package Pex::ELFInfo;
use strict;

# Usage: new(File => $path, Debug => 1)
sub new {
    my $class = shift;
    my $self = bless {}, $class;
    return $self->_Init(@_);
}

sub _Init {
    my $self = shift;
    my %args = @_;

    $self->{'Raw'}         = "";
    $self->{'LastError'}   = "";
    $self->{'ELF_HDR'}     = { };
    $self->{'ELF_PHDR'}    = { };
    $self->{'BaseAddr'}	   = "";
    $self->{'OPTS'}        = \%args;

    $self->LoadImage;
    return $self;
}

sub Debug {
    my $self = shift;
    if (@_) { $self->{'OPTS'}->{'Debug'} = shift() }
    return $self->{'OPTS'}->{'Debug'};
}

sub LastError {
    my $self = shift;
    if (@_) { $self->{'LastError'} = shift() }
    return $self->{'LastError'};
}

sub Raw {
    my $self = shift;
    return $self->{'Raw'};
}

sub ElfHeader {
    my $self = shift;
    my $name = shift;
    if (exists($self->{'ELF_HDR'}->{$name})) {
        return $self->{'ELF_HDR'}->{$name};
    }
    return;
}

sub ElfHeaders {
    my $self = shift;
    return keys( %{ $self->{'ELF_HDR'} } );
}

sub ProgramHeader {
    my $self = shift;
    my $num = shift;
    my $name = shift;

    if (exists($self->{'ELF_PHDR'}->[$num]->{$name})) {
        return $self->{'ELF_PHDR'}->[$num]->{$name};
    }
    return;
}

sub ProgramHeaders {
    my $self = shift;    
    return keys( %{ $self->{'ELF_PHDR'} } );
}

sub ImageBase {
    my $self = shift;
    if (@_) {
        $self->{'BaseAddr'} = hex(shift());
    }
    return $self->{'BaseAddr'};
}

sub LoadImage {
    my $self  = shift;
    my $file  = $self->{'OPTS'}->{'File'};
    my $debug = $self->{'OPTS'}->{'Debug'};
    
    my $data;   
    local *X;
        
    if (! open(X, "<$file")) {
        $self->LastError("Could not open file: $!");
        return;
    }
    
    while(<X>) { $data .= $_ }
    close(X);

    # Strip the leading path from the file name
    if ((my $ls = rindex($file, "/")) != -1) {
        $file = substr($file, $ls+1);
    }
    
    $self->{'FILENAME'} = $file;
    
    
    $self->{'Raw'} = $data;
   
    if(unpack('a4', substr($data, 0, 4)) ne "\177ELF") 
    {
        $self->LastError('File does not match ELF format');
        return(undef);
    }

    my $class = unpack('C', substr($data, 4, 1));
    my $encoding = unpack('C', substr($data, 5, 1));
    my $int16;
    my $int32;
    my %ELF_HDR;
    my @ELF_PHDRS;
  
    if($class == 1) # ELFCLASS32
    {
    	if($encoding == 1) # ELFDATA2LSB
    	{
	    $int16 = "v";
	    $int32  = "V";
	}
	elsif($encoding == 2) #ELFDATA2MSB
	{
	    $int16 = "n";
	    $int32  = "N";
	}
	else
	{
		$self->LastError("Invalid data encoding");
		return(undef);
	}
    } 
    else 
    {
    	$self->LastError("Invalid or unsupported class");
	return (undef);
    }
  
    $ELF_HDR{'e_ident'}		= unpack('a16', substr($data,  0, 16));
    $ELF_HDR{'e_type'}		= unpack($int16, substr($data, 16, 2));
    $ELF_HDR{'e_machine'}	= unpack($int16, substr($data, 18, 2));
    $ELF_HDR{'e_version'}	= unpack($int32, substr($data, 20, 4));
    $ELF_HDR{'e_entry'}		= unpack($int32, substr($data, 24, 4));
    $ELF_HDR{'e_phoff'}		= unpack($int32, substr($data, 28, 4));
    $ELF_HDR{'e_shoff'}		= unpack($int32, substr($data, 32, 4));
    $ELF_HDR{'e_flags'}		= unpack($int32, substr($data, 36, 4));
    $ELF_HDR{'e_ehsize'}	= unpack($int16, substr($data, 40, 2));
    $ELF_HDR{'e_phentsize'}	= unpack($int16, substr($data, 42, 2));
    $ELF_HDR{'e_phnum'}		= unpack($int16, substr($data, 44, 2));
    $ELF_HDR{'e_shentsize'}	= unpack($int16, substr($data, 46, 2));
    $ELF_HDR{'e_shnum'}		= unpack($int16, substr($data, 48, 2));
    $ELF_HDR{'e_shstrndx'}	= unpack($int16, substr($data, 50, 2));

    my $phoff 		= $ELF_HDR{'e_phoff'};
    my $phentsize   	= $ELF_HDR{'e_phentsize'};
    my $phnum  		= $ELF_HDR{'e_phnum'};
    my $phdr_data 	= substr($data, $phoff, $phnum * $phentsize);

    for (my $i = 0; $i < $phnum; $i++)
    {
	my %ELF_PHDR;
        my $phdr = $phoff + ($phentsize * $i);	
	
	$ELF_PHDR{'p_type'}	= unpack($int32, substr($data, $phdr,   4));
	$ELF_PHDR{'p_offset'}	= unpack($int32, substr($data, $phdr +  4, 4));
	$ELF_PHDR{'p_vaddr'}	= unpack($int32, substr($data, $phdr +  8, 4));
	$ELF_PHDR{'p_paddr'}	= unpack($int32, substr($data, $phdr + 16, 4));
	$ELF_PHDR{'p_filesz'}	= unpack($int32, substr($data, $phdr + 20, 4));
	$ELF_PHDR{'p_memsz'}	= unpack($int32, substr($data, $phdr + 24, 4));
	$ELF_PHDR{'p_flags'}	= unpack($int32, substr($data, $phdr + 28, 4));
	$ELF_PHDR{'p_align'}	= unpack($int32, substr($data, $phdr + 32, 4));
	
	if($ELF_PHDR{'p_type'} == 1 && $self->{'BaseAddr'} == 0)
	{
		$self->{'BaseAddr'} = $ELF_PHDR{'p_vaddr'};
	}
	$ELF_PHDRS[$i] = \%ELF_PHDR;	
    }  

    $self->{'ELF_HDR'}	= \%ELF_HDR;
    $self->{'ELF_PHDR'}	= \@ELF_PHDRS;
    return($self);    
}

sub OffsetToRVA {
    my ($self, $offset) = @_;
    return 0 if ! defined($offset);

    for(my $i = 0; $i < $self->{'ELF_HDR'}->{'e_phnum'}; $i++)
    {
	my $phdr = $self->{'ELF_PHDR'}->[$i];
	# skip if not PT_LOAD
	next if($phdr->{'p_type'} != 0x1);
	if($offset >= $phdr->{'p_offset'} &&
	   $offset < $phdr->{'p_offset'} + 
	   $phdr->{'p_filesz'})
	{
		return $offset + $self->{'BaseAddr'};
	}
    }
}

sub RVAToOffset {
    my ($self, $virtual) = @_;
    return 0 if ! defined($virtual);
	    
    for(my $i = 0; $i < $self->{'ELF_HDR'}->{'e_phnum'}; $i++)
    {
	my $phdr = $self->{'ELF_PHDR'}->[$i];
	# skip if not PT_LOAD
	next if($phdr->{'p_type'} != 0x1);
	if($virtual >= $self->{'BaseAddr'} &&
	$virtual <= $self->{'BaseAddr'} +  $phdr->{'p_filesz'})
	{
		return $virtual - $self->{'BaseAddr'};
	}
    }
    return;
}



sub OffsetToVirtual {
    my ($self, $offset) = @_;
    return $self->OffsetToRVA($offset);
}

sub VirtualToOffset {
    my ($self, $virtual) = @_;
    return $self->RVAToOffset($virtual);
}

sub _V2O {
    my $self = shift;
    return $self->VirtualToOffset(@_);
}

sub _RV2O {
    my $self = shift;
    return $self->Offset(@_);
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

sub _DebugLog {
    my $self = shift;
    my $data = shift;
    
    return if ! $self->Debug;
    my @src = caller(1);
    print STDERR scalar(localtime())." ".
          $src[3]." ".$self->{'FILENAME'}.
          " $data\n";
}
1;
