#!/usr/bin/perl
###############

##
#         Name: SMB.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
#

# This module is based on pysmb, the Nessus smb_nt.inc, and Authen::NTLM
# Its a ghetto hack, but it works for what we need

package Pex::SMB;
use Pex;
use Pex::Struct;
use strict;


###############################
# constants ripped from pysmb #
###############################

use constant {
# Shared Device Type
  SHARED_DISK => 0x00,
  SHARED_PRINT_QUEUE => 0x01,
  SHARED_DEVICE => 0x02,
  SHARED_IPC => 0x03,

# Extended attributes mask
  ATTR_ARCHIVE => 0x020,
  ATTR_COMPRESSED => 0x800,
  ATTR_NORMAL => 0x080,
  ATTR_HIDDEN => 0x002,
  ATTR_READONLY => 0x001,
  ATTR_TEMPORARY => 0x100,
  ATTR_DIRECTORY => 0x010,
  ATTR_SYSTEM => 0x004,

# Service Type
  SERVICE_DISK => 'A:',
  SERVICE_PRINTER => 'LPT1:',
  SERVICE_IPC => 'IPC',
  SERVICE_COMM => 'COMM',
  SERVICE_ANY => '?????',

# Server Type (Can be used to mask with SMBMachine.get_type() or SMBDomain.get_type())
  SV_TYPE_WORKSTATION => 0x00000001,
  SV_TYPE_SERVER      => 0x00000002,
  SV_TYPE_SQLSERVER   => 0x00000004,
  SV_TYPE_DOMAIN_CTRL => 0x00000008,
  SV_TYPE_DOMAIN_BAKCTRL => 0x00000010,
  SV_TYPE_TIME_SOURCE    => 0x00000020,
  SV_TYPE_AFP            => 0x00000040,
  SV_TYPE_NOVELL         => 0x00000080,
  SV_TYPE_DOMAIN_MEMBER => 0x00000100,
  SV_TYPE_PRINTQ_SERVER => 0x00000200,
  SV_TYPE_DIALIN_SERVER => 0x00000400,
  SV_TYPE_XENIX_SERVER  => 0x00000800,
  SV_TYPE_NT        => 0x00001000,
  SV_TYPE_WFW       => 0x00002000,
  SV_TYPE_SERVER_NT => 0x00004000,
  SV_TYPE_POTENTIAL_BROWSER => 0x00010000,
  SV_TYPE_BACKUP_BROWSER    => 0x00020000,
  SV_TYPE_MASTER_BROWSER    => 0x00040000,
  SV_TYPE_DOMAIN_MASTER     => 0x00080000,
  SV_TYPE_LOCAL_LIST_ONLY => 0x40000000,
  SV_TYPE_DOMAIN_ENUM     => 0x80000000,

# Options values for SMB.stor_file and SMB.retr_file
  SMB_O_CREAT => 0x10,   # Create the file if file does not exists. Otherwise, operation fails.
  SMB_O_EXCL => 0x00,    # When used with SMB_O_CREAT, operation fails if file exists. Cannot be used with SMB_O_OPEN.
  SMB_O_OPEN => 0x01,    # Open the file if the file exists
  SMB_O_TRUNC => 0x02,   # Truncate the file if the file exists

# Share Access Mode;
  SMB_SHARE_COMPAT => 0x00,
  SMB_SHARE_DENY_EXCL => 0x10,
  SMB_SHARE_DENY_WRITE => 0x20,
  SMB_SHARE_DENY_READEXEC => 0x30,
  SMB_SHARE_DENY_NONE => 0x40,
  SMB_ACCESS_READ => 0x00,
  SMB_ACCESS_WRITE => 0x01,
  SMB_ACCESS_READWRITE => 0x02,
  SMB_ACCESS_EXEC => 0x03,

# SMB Command Codes
  SMB_COM_CREATE_DIR => 0x00,
  SMB_COM_DELETE_DIR => 0x01,
  SMB_COM_CLOSE => 0x04,
  SMB_COM_DELETE => 0x06,
  SMB_COM_RENAME => 0x07,
  SMB_COM_CHECK_DIR => 0x10,
  SMB_COM_READ_RAW => 0x1a,
  SMB_COM_WRITE_RAW => 0x1d,
  SMB_COM_TRANSACTION => 0x25,
  SMB_COM_TRANSACTION2 => 0x32,
  SMB_COM_OPEN_ANDX => 0x2d,
  SMB_COM_READ_ANDX => 0x2e,
  SMB_COM_WRITE_ANDX => 0x2f,
  SMB_COM_TREE_DISCONNECT => 0x71,
  SMB_COM_NEGOTIATE => 0x72,
  SMB_COM_SESSION_SETUP_ANDX => 0x73,
  SMB_COM_LOGOFF => 0x74,
  SMB_COM_TREE_CONNECT_ANDX => 0x75,

# Security Share Mode (Used internally by SMB class);
  SECURITY_SHARE_MASK => 0x01,
  SECURITY_SHARE_SHARE => 0x00,
  SECURITY_SHARE_USER => 0x01,

# Security Auth Mode (Used internally by SMB class);
  SECURITY_AUTH_MASK => 0x02,
  SECURITY_AUTH_ENCRYPTED => 0x02,
  SECURITY_AUTH_PLAINTEXT => 0x00,


# Raw Mode Mask (Used internally by SMB class. Good for dialect up to and including LANMAN2.1);
  RAW_READ_MASK => 0x01,
  RAW_WRITE_MASK => 0x02,

# Capabilities Mask (Used internally by SMB class. Good for dialect NT LM 0.12);
  CAP_RAW_MODE => 0x0001,
  CAP_MPX_MODE => 0x0002,
  CAP_UNICODE => 0x0004,
  CAP_LARGE_FILES => 0x0008,
  CAP_EXTENDED_SECURITY => 0x80000000,

# Flags1 Mask;
  FLAGS1_PATHCASELESS => 0x08,

# Flags2 Mask;
  FLAGS2_LONG_FILENAME => 0x0001,
  FLAGS2_UNICODE => 0x8000,

};

##############################
## pre-generated structures ##
##############################

# NetBIOS Session Structure
my $STSession = Pex::Struct->new
([
    'type'          => 'u_8',
    'flags'         => 'u_8',
    'requestLen'    => 'b_u_16',
    'request'       => 'string'
]);
$STSession->SetSizeField( 'request' => 'requestLen' );
$STSession->Set
(
    'type'  => 0,
    'flags' => 0,
);

# SMB Packet Structure
my $STSMB = Pex::Struct->new
([
    'smbmagic'      => 'b_u_32',
    'command'       => 'u_8',
    'error_class'   => 'u_8',
    'reserved1'     => 'u_8',
    'error_code'    => 'b_u_16',
    'flags1'        => 'u_8',
    'flags2'        => 'l_u_16',
    'pid_high'      => 'l_u_16',
    'signature1'    => 'l_u_32',
    'signature2'    => 'l_u_32',
    'reserved2'     => 'l_u_16',
    'tree_id'       => 'l_u_16',
    'process_id'    => 'l_u_16',
    'user_id',      => 'l_u_16',
    'multiplex_id'  => 'l_u_16',
    'request'       => 'string',
]);
$STSMB->Set
(
    'smbmagic'      => 0xff534d42, # \xffSMB
    'command'       => 0,
    'error_class'   => 0,
    'reserved1'     => 0,
    'error_code'    => 0,
    'flags1'        => 0,
    'flags2'        => 0,
    'pid_high'      => 0,
    'signature1'    => 0,
    'signature2'    => 0,
    'reserved2'     => 0,
    'tree_id'       => 0,
    'process_id'    => $$,
    'user_id'       => 0,
    'multiplex_id'  => 0,
    'request'       => '',
);

# Protocol Negotiation Header
my $STNetbios = Pex::Struct->new
([
    'word_count'    => 'u_8',
    'byte_count'    => 'l_u_16',
    'data'          => 'string',
]);
$STNetbios->SetSizeField( 'data' => 'byte_count' );
$STNetbios->Set
(
    'word_count'    => 0,
    'byte_count'    => 0,
);

# LANMAN Protocol Negotiation Response
my $STNegResLM = Pex::Struct->new
([
    'word_count'    => 'u_8',
    'dialect'       => 'l_u_16',
    'sec_mode'      => 'l_u_16',
    'max_buff'      => 'l_u_16',
    'max_mpx'       => 'l_u_16',
    'max_vcs'       => 'l_u_16',
    'raw_mode'      => 'l_u_16',
    'sess_key'      => 'l_u_32',
    'dos_time'      => 'l_u_16',
    'dos_date'      => 'l_u_16',
    'time_zone'     => 'l_u_16',
    'key_len'       => 'l_u_16',
    'reserved'      => 'l_u_16',
    'bcc_len'       => 'l_u_16',
    'enc_key'       => 'string',
]);
$STNegResLM->SetSizeField( 'enc_key' => 'key_len' );
$STNegResLM->Set
(
    'word_count'    => 0,
    'dialect'       => 0,
    'sec_mode'      => 0,
    'max_buff'      => 0,
    'max_mpx'       => 0,
    'max_vcs'       => 0,
    'raw_mode'      => 0,
    'sess_key'      => 0,
    'dos_time'      => 0,
    'dos_date'      => 0,
    'time_zone'     => 0,
    'key_len'       => 0,
    'reserved'      => 0,
    'bcc_len'       => 0,
);

# NTLM Protocol Negotiation Response
my $STNegResNT = Pex::Struct->new
([
    'word_count'    => 'u_8',
    'dialect'       => 'l_u_16',
    'sec_mode'      => 'u_8',
    'max_mpx'       => 'l_u_16',
    'max_vcs'       => 'l_u_16',
    'max_buff'      => 'l_u_32',
    'max_raw'       => 'l_u_32',    
    'sess_key'      => 'l_u_32',
    'caps'          => 'l_u_32',
    'dos_time'      => 'l_u_32',
    'dos_date'      => 'l_u_32',
    'time_zone'     => 'l_u_16',
    'key_len'       => 'u_8',
    'bcc_len'       => 'l_u_16',
    'enc_key'       => 'string',
    'domain'        => 'string',
    
]);
$STNegResNT->SetSizeField( 'enc_key' => 'key_len' );
$STNegResNT->Set
(
    'word_count'    => 0,
    'dialect'       => 0,
    'sec_mode'      => 0,
    'max_mpx'       => 0,
    'max_vcs'       => 0,
    'max_buff'      => 0,
    'max_raw'       => 0,
    'sess_key'      => 0,
    'caps'          => 0,
    'dos_time'      => 0,
    'dos_date'      => 0,
    'time_zone'     => 0,
    'key_len'       => 0,
    'bcc_len'       => 0,
);


# SMB Session Setup LM
my $STSetupXLM = Pex::Struct->new
([
    'word_count'    => 'u_8',
    'x_cmd'         => 'u_8',
    'reserved1'     => 'u_8',
    'x_off'         => 'l_u_16',    
    'max_buff'      => 'l_u_16',
    'max_mpx'       => 'l_u_16',
    'vc_num'        => 'l_u_16',
    'sess_key'      => 'l_u_32',
    'pass_len'      => 'l_u_16',
    'reserved2'     => 'l_u_32',
    'bcc_len'       => 'l_u_16',
    'request'       => 'string',
]);
$STSetupXLM->SetSizeField( 'request' => 'bcc_len' );
$STSetupXLM->Set
(
    'word_count'    => 0,
    'x_cmd'         => 0,
    'reserved1'     => 0,
    'x_off'         => 0,  
    'max_buff'      => 0,
    'max_mpx'       => 0,
    'vc_num'        => 0,
    'sess_key'      => 0,
    'pass_len'      => 0,
    'reserved2'     => 0,
    'bcc_len'       => 0,
);

# SMB Session Setup NT
my $STSetupXNT = Pex::Struct->new
([
    'word_count'    => 'u_8',
    'x_cmd'         => 'u_8',
    'reserved1'     => 'u_8',
    'x_off'         => 'l_u_16',    
    'max_buff'      => 'l_u_16',
    'max_mpx'       => 'l_u_16',
    'vc_num'        => 'l_u_16',
    'sess_key'      => 'l_u_32',
    'pass_len_lm'   => 'l_u_16',
    'pass_len_nt'   => 'l_u_16',
    'reserved2'     => 'l_u_32',
    'caps'          => 'l_u_32',
    'bcc_len'       => 'l_u_16',
    'request'       => 'string',
]);
$STSetupXNT->SetSizeField( 'request' => 'bcc_len' );
$STSetupXNT->Set
(
    'word_count'    => 0,
    'x_cmd'         => 0,
    'reserved1'     => 0,
    'x_off'         => 0,  
    'max_buff'      => 0,
    'max_mpx'       => 0,
    'vc_num'        => 0,
    'sess_key'      => 0,
    'pass_len_lm'   => 0,
    'pass_len_nt'   => 0,
    'reserved2'     => 0,
    'caps'          => 0,
    'bcc_len'       => 0,
);

# SMB Session SetupX Response (w/null X)
my $STSetupXRes = Pex::Struct->new
([
    'word_count'    => 'u_8',
    'x_cmd'         => 'u_8',
    'reserved1'     => 'u_8',
    'x_off'         => 'l_u_16',    
    'action'        => 'l_u_16',
    'bcc_len'       => 'l_u_16',
    'request'       => 'string',
]);
$STSetupXRes->Set
(
    'word_count'    => 0,
    'x_cmd'         => 0,
    'reserved1'     => 0,
    'x_off'         => 0,  
    'action'        => 0,
    'bcc_len'       => 0,
);



my $STTConnectX = Pex::Struct->new
([
    'word_count'    => 'u_8',
    'x_cmd'         => 'u_8',
    'reserved1'     => 'u_8',
    'x_off'         => 'l_u_16',
    'flags'         => 'l_u_16', 
    'pass_len'      => 'l_u_16',
    'bcc_len'       => 'l_u_16',
    'request'       => 'string',
]);
$STTConnectX->SetSizeField( 'request' => 'bcc_len' );
$STTConnectX->Set
(
    'word_count'    => 0,
    'x_cmd'         => 0,
    'reserved1'     => 0,
    'x_off'         => 0,  
    'flags'         => 0,
    'pass_len'      => 0,
    'bcc_len'       => 0,
);


# SMB Session TreeConnectX Response (w/null X)
my $STTConnectXRes = Pex::Struct->new
([
    'word_count'    => 'u_8',
    'x_cmd'         => 'u_8',
    'reserved1'     => 'u_8',
    'x_off'         => 'l_u_16',    
    'support'       => 'l_u_16',
    'bcc_len'       => 'l_u_16',
    'request'       => 'string',
]);
$STTConnectXRes->SetSizeField( 'request' => 'bcc_len' );
$STTConnectXRes->Set
(
    'word_count'    => 0,
    'x_cmd'         => 0,
    'reserved1'     => 0,
    'x_off'         => 0,  
    'support'       => 0,
    'bcc_len'       => 0,
);


my $STTrans = Pex::Struct->new
([
    'word_count'        => 'u_8',
    'param_count_tot'   => 'l_u_16',
    'data_count_tot'    => 'l_u_16',
    'param_count_max'   => 'l_u_16',
    'data_count_max'    => 'l_u_16',
    'setup_count_max'   => 'u_8',
    'reserved1'         => 'u_8',,
    'flags'             => 'l_u_16',
    'timeout'           => 'l_u_32',
    'reserved2'         => 'l_u_16',
    'param_count'       => 'l_u_16',
    'param_offset'      => 'l_u_16',
    'data_count'        => 'l_u_16',
    'data_offset'       => 'l_u_16',
    'setup_count'       => 'u_8',
    'reserved3'         => 'u_8',
    'setup_data'        => 'string',
    'bcc_len'           => 'l_u_16',
    'request'           => 'string'  
]);
$STTrans->SetSizeField( 'request' => 'bcc_len' );
$STTrans->Set
(
    'word_count'        => 0,
    'param_count_tot'   => 0,
    'data_count_tot'    => 0,
    'param_count_max'   => 0,
    'data_count_max'    => 0,
    'setup_count_max'   => 0,
    'reserved1'         => 0,
    'flags'             => 0,
    'timeout'           => 0,
    'reserved2'         => 0,
    'param_count'       => 0,
    'param_offset'      => 0,
    'data_count'        => 0,
    'data_offset'       => 0,
    'setup_count'       => 0,
    'reserved3'         => 0,
    'bcc_len'           => 0,
    'request'           => 0,
);


my $STCreateX = Pex::Struct->new
([
    'word_count'    => 'u_8',
    'x_cmd'         => 'u_8',
    'reserved1'     => 'u_8',
    'x_off'         => 'l_u_16',
    'reserved2'     => 'u_8',
    'filename_len'  => 'l_u_16',
    'create_flags'  => 'l_u_32',
    'root_fid'      => 'l_u_32',
    'access_mask'   => 'l_u_32',
    'alloc_low'     => 'l_u_32',
    'alloc_high'    => 'l_u_32',
    'attribs'       => 'l_u_32',
    'share_access'  => 'l_u_32', 
    'disposition'   => 'l_u_32',
    'create_opts'   => 'l_u_32',
    'impersonation' => 'l_u_32',
    'sec_flags'     => 'u_8',
    'bcc_len'       => 'l_u_16',
    'request'       => 'string',
]);
$STCreateX->SetSizeField( 'request' => 'bcc_len' );
$STCreateX->Set
(
    'word_count'    => 0,
    'x_cmd'         => 0,
    'reserved1'     => 0,
    'x_off'         => 0,
    'reserved2'     => 0,
    'filename_len'  => 0,
    'create_flags'  => 0,
    'root_fid'      => 0,
    'access_mask'   => 0,
    'create_flags'  => 0,
    'alloc_low'     => 0,
    'alloc_high'    => 0,
    'attribs'       => 0,
    'share_access'  => 0,
    'disposition'   => 0,
    'create_opts'   => 0,
    'impersonation' => 0,
    'sec_flags'     => 0,
    'bcc_len'       => 0,
);



my $STCreateXRes = Pex::Struct->new
([
    'word_count'        => 'u_8',
    'x_cmd'             => 'u_8',
    'reserved1'         => 'u_8',
    'x_off'             => 'l_u_16',
    'oplock'            => 'u_8',
    'fid'               => 'l_u_16',
    'action'            => 'l_u_32',
    'create_time_low'   => 'l_u_32',
    'create_time_high'  => 'l_u_32',
    'access_time_low'   => 'l_u_32',
    'access_time_high'  => 'l_u_32',
    'write_time_low'    => 'l_u_32',
    'write_time_high'   => 'l_u_32',
    'change_time_low'   => 'l_u_32',
    'change_time_high'  => 'l_u_32',   
    'attribs'           => 'l_u_32',
    'alloc_low'         => 'l_u_32',
    'alloc_high'        => 'l_u_32',
    'eof_low'           => 'l_u_32',
    'eof_high'          => 'l_u_32',    
    'file_type'         => 'l_u_16',
    'ipc_state'         => 'l_u_16',
    'is_dir'            => 'u_8',
    'bcc_len'       => 'l_u_16',
    'request'       => 'string',
]);
$STCreateXRes->SetSizeField( 'request' => 'bcc_len' );
$STCreateXRes->Set
(
    'word_count'        => 0,
    'x_cmd'             => 0,
    'reserved1'         => 0,
    'x_off'             => 0,
    'oplock'            => 0,
    'fid'               => 0,
    'action'            => 0,
    'create_time_low'   => 0,
    'create_time_high'  => 0,
    'access_time_low'   => 0,
    'access_time_high'  => 0,
    'write_time_low'    => 0,
    'write_time_high'   => 0,
    'change_time_low'   => 0,
    'change_time_high'  => 0,
    'attribs'           => 0,
    'alloc_low'         => 0,
    'alloc_high'        => 0,
    'eof_low'           => 0,
    'eof_high'          => 0,
    'file_type'         => 0,
    'ipc_state'         => 0,
    'is_dir'            => 0,
    'bcc_len'           => 0,
    'request'           => 0,
);


my $STWriteX = Pex::Struct->new
([
    'word_count'    => 'u_8',
    'x_cmd'         => 'u_8',
    'reserved1'     => 'u_8',
    'x_off'         => 'l_u_16',
    'fid'           => 'l_u_16',   
    'offset'        => 'l_u_32',
    'reserved2'     => 'l_u_32',
    'write_mode'    => 'l_u_16',
    'remaining'     => 'l_u_16',
    'data_len_high' => 'l_u_16',
    'data_len_low'  => 'l_u_16',
    'data_offset'   => 'l_u_16',
    'data_offset_high' => 'l_u_32',
    'bcc_len'       => 'l_u_16',
    'request'       => 'string',
]);
$STWriteX->SetSizeField( 'request' => 'bcc_len' );
$STWriteX->Set
(
    'word_count'    => 0,
    'x_cmd'         => 0,
    'reserved1'     => 0,
    'x_off'         => 0,
    'fid'           => 0,
    'offset'        => 0,
    'reserved2'     => 0xffffffff,
    'write_mode'    => 0,
    'remaining'     => 0,
    'data_len_high' => 0,
    'data_len_low'  => 0,
    'data_offset'   => 0,
    'data_offset_high' => 0,
    'bcc_len'       => 0,
);

my $STWriteXRes = Pex::Struct->new
([
    'word_count'    => 'u_8',
    'x_cmd'         => 'u_8',
    'reserved1'     => 'u_8',
    'x_off'         => 'l_u_16',
    'fid'           => 'l_u_16',   
    'count_low'     => 'l_u_16',
    'remaining'     => 'l_u_16',
    'count_high'    => 'l_u_16',
    'reserved2'     => 'l_u_16',
    'bcc_len'       => 'l_u_16',
    'request'       => 'string',
]);
$STWriteXRes->SetSizeField( 'request' => 'bcc_len' );
$STWriteXRes->Set
(
    'word_count'    => 0,
    'x_cmd'         => 0,
    'reserved1'     => 0,
    'x_off'         => 0,
    'fid'           => 0,
    'count_low'     => 0,
    'remaining'     => 0,
    'count_high'    => 0,
    'reserved2'     => 0,
    'bcc_len'       => 0,
);


######################################
# This actual class code starts here #
######################################

sub new {
    my $cls = shift();
    my $arg = shift() || { };
    my $self = bless $arg, $cls;
    $self->NativeOS('Unix');
    $self->NativeLM('Metasploit Framework');
    return $self;
}

sub Socket { 
    my $self = shift;
    $self->{'Socket'} = shift if @_;
    return $self->{'Socket'};
}

sub Error {
    my $self = shift;
    $self->{'LastError'} = shift if @_;    
    return $self->{'LastError'};
}

sub ClearError {
    my $self = shift;
    delete($self->{'LastError'});
}

sub Encrypted {
    my $self = shift;
    $self->{'Encrypted'} = shift if @_;
    return $self->{'Encrypted'};
}

sub Dialect {
    my $self = shift;
    $self->{'Dialect'} = shift if @_;
    return $self->{'Dialect'};
}

sub SessionID {
    my $self = shift;
    $self->{'SessionID'} = shift if @_;
    return $self->{'SessionID'};
}

sub ChallengeKey {
    my $self = shift;
    $self->{'ChallengeKey'} = shift if @_;
    return $self->{'ChallengeKey'};
}

sub NativeOS {
    my $self = shift;
    $self->{'NativeOS'} = shift if @_;
    return $self->{'NativeOS'};
}

sub NativeLM {
    my $self = shift;
    $self->{'NativeLM'} = shift if @_;
    return $self->{'NativeLM'};
}

sub DefaultDomain {
    my $self = shift;
    $self->{'DefaultDomain'} = shift if @_;
    return $self->{'DefaultDomain'};
}

sub AuthUser {
    my $self = shift;
    $self->{'AuthUser'} = shift if @_;
    return $self->{'AuthUser'};
}

sub AuthUserID {
    my $self = shift;
    $self->{'AuthUserID'} = shift if @_;
    return $self->{'AuthUserID'};
}

sub MultiplexID {
    my $self = shift;
    if (! exists($self->{'MultiplexID'})) {
        $self->{'MultiplexID'} = rand() * 0xffff;
    }
    return $self->{'MultiplexID'};
}

sub TreeID {
    my $self = shift;
    
    if (! $self->{'Trees'}) {
        $self->{'Trees'} = { };
    }
    
    my $trees = $self->{'Trees'};
    my $tree_name = shift if @_;
    my $tree_tid  = shift if @_;
    
    if ($tree_tid) {
        $trees->{$tree_name} = $tree_tid;
    }
    
    if ($tree_name) {
        return $trees->{$tree_name};
    }
}

sub LastTreeID {
    my $self = shift;
    $self->{'LastTreeID'} = shift if @_;
    return $self->{'LastTreeID'};
}

sub LastFileID {
    my $self = shift;
    $self->{'LastFileID'} = shift if @_;
    return $self->{'LastFileID'};
}


sub CryptLM {
    my $self = shift;
    my $pass = shift;
    my $chal = shift;
    
    $pass = substr($pass, 0, 14);
    $pass =~ tr/a-z/A-Z/;
    $pass .= ("\x00" x (14-length($pass)));
    my $res = SMBDES::E_P16($pass);
    $res .= ("\x00" x (21-length($res)));
    $res = SMBDES::E_P24($res, $chal);
    return $res;
}

sub CryptNT {
    my $self = shift;
    my $pass = shift;
    my $chal = shift;
    
    my $res = SMBMD4::MD4($self->NTUnicode($pass));
    $res .= ("\x00" x (21-length($res)));
    $res = SMBDES::E_P24($res, $chal);
    return $res;
}

sub NTUnicode {
    my $self = shift;
    my $data = shift;
    my $res;
    foreach (split(//, $data)) {
        $res.= pack('v', ord($_));
    }
    return $res;
}

sub NBName {
    my $self = shift();
    my $name = shift() || $self;
    my $res;
    
    for (0 .. 15) {
        if ($_ >= length($name)) {
            $res .= "CA";
        } else {
            my $o = ord(uc(substr($name, $_)));
            $res .= pack('CC', ($o / 16) + 0x41, ($o % 16) + 0x41);
        }
    }
    return $res;
}

sub NBRedir {
    my $self = shift();
    return ("CA" x 15)."AA";
}

sub SMBRecv {
    my $self = shift();
    my $sock = $self->Socket;
    my $head = $sock->Recv(4);
    
    if (! $head || length($head) != 4) {
        $self->Error('Incomplete header read');
        return;
    }
    
    my $len = unpack('n', substr($head, 2, 2));
    
    # Return just the header for empty responses
    if ($len == 0) {
        return $head;
    }
    
    my $end = $sock->Recv($len);
    
    if (! $end || length($end) != $len) {
        $self->Error('Incomplete body read');
    }
    return($head.$end);
}

sub SMBSessionRequest {
    my $self = shift;
    my $name = shift;
    my $sock = $self->Socket;
      
    my $data = "\x20".$self->NBName($name)."\x00".
               "\x20".$self->NBRedir."\x00";
    
    my $ask = $STSession->copy;
    $ask->Set('type' => 0x81, 'request' => $data);  
    
    $sock->Send($ask->Fetch);
    
    my $res = $self->SMBRecv();
    
    if (! $res) {
        $self->Error('Session request failed on read');
        return;
    }
    
    my $smb_res = $STSession->copy;
    $smb_res->Fill($res);
    
    # Handle negative session request responses
    if ($smb_res->Get('type') == 0x83) {
        $self->Error('Session denied with code '.ord($smb_res->Get('request')));
        return;
    }
   
    if ($smb_res->Get('type') != 0x82) {
        $self->Error('Session returned unknown response: '.$smb_res->Get('type'));
        return; 
    }
    
    return $smb_res;
}

sub SMBNegotiate {
    my $self = shift;
    my $sock = $self->Socket;
    my $dias = shift;
 
    return if $self->Error;
 
    my $ses = $STSession->copy;
    my $smb = $STSMB->copy;
    my $neg = $STNetbios->copy;
    
    my @dialects =
    (
        "METASPLOIT",
        "LANMAN1.0",
        "LM1.2X002",
    );
    
    if ($self->Encrypted) {
        push @dialects, "NT LANMAN 1.0";
        push @dialects, "NT LM 0.12";
    }
    
    my $offer;
    if (! $dias) {
        foreach (@dialects) { $offer.= "\x02".$_."\x00" }
    } else {
        $offer = $dias;
    }

    $neg->Set ('data' => $offer);
    
    $smb->Set
    (
        'command'       => SMB_COM_NEGOTIATE,
        'flags1'        => 0x18,
        'flags2'        => 0x2001,
        'multiplex_id'  => $self->MultiplexID,
        'request'       => $neg->Fetch
    );
    
    $ses->Set('type' => 0, 'flags' => 0, 'request' => $smb->Fetch);
    $sock->Send($ses->Fetch);
    my $res = $self->SMBRecv();
    
    if (! $res) {
        $self->Error('Negotiate failed due to null response');
        return;
    }
    
    my $ses_res = $STSession->copy;
    $ses_res->Fill($res);

    my $smb_res = $STSMB->copy;
    $smb_res->Fill($ses_res->Get('request'));
    $smb_res->Set('request' => substr($ses_res->Get('request'), $smb_res->Length));

    if ($smb_res->Get('error_class') != 0) {
        $self->Error('Negotiate returned NT status '.$smb_res->Get('error_class'));
        return;
    }

    if ($smb_res->Get('command') != SMB_COM_NEGOTIATE) {
        $self->Error('Negotiate returned command '.$smb_res->Get('command'));
        return;
    }


    # Parse the negotiation response based on the dialect recieved
    my $dia = unpack('v', substr($smb_res->Get('request'), 1, 2));
    $self->Dialect($dialects[$dia]);

    my $neg_res;
    
    if ($self->Dialect =~ /^(LANMAN1.0|LM1.2X002)$/) {
        $neg_res = $STNegResLM->copy;
    } 

    if ($self->Dialect =~ /^(NT LANMAN 1.0|NT LM 0.12)$/) {
        $neg_res = $STNegResNT->copy;
    }
    
    if (! $neg_res) {
        $self->Error('Negotiate returned unsupported dialect '.$dia);
        return;       
    }
    
    $neg_res->Fill($smb_res->Get('request'));

    my $extra_len = $neg_res->Get('bcc_len') - $neg_res->Get('key_len');
    if ($extra_len) {
        $neg_res->Set('domain' => substr($smb_res->Get('request'), ($extra_len * -1)));
        $self->DefaultDomain($neg_res->Get('domain'));
    }
    
    $self->ChallengeKey($neg_res->Get('enc_key'));
    $self->SessionID($neg_res->Get('sess_key'));
    
    return $neg_res;
}

sub SMBSessionSetup {
    my $self = shift;
    
    return if $self->Error;
   
    if ($self->Dialect =~ /^(LANMAN1.0|LM1.2X002)$/) {
        return $self->SMBSessionSetupClear(@_);
    } 

    if ($self->Dialect =~ /^(NT LANMAN 1.0|NT LM 0.12)$/) {
        return $self->SMBSessionSetupNTLM(@_);
    }
    
    $self->Error('SMBSessionSetup does not know dialect '.$self->Dialect);
    return;
}

sub SMBSessionSetupClear {
    my $self = shift;
    my $user = @_ ? shift : "";
    my $pass = @_ ? shift : "";
    my $wdom = @_ ? shift : "";
    my $sock = $self->Socket;
    
    return if $self->Error;
       
    my $data = $pass . "\x00".
               $user . "\x00".
               $wdom . "\x00".
               $self->NativeOS."\x00".
               $self->NativeLM."\x00";
    
    my $log = $STSetupXLM->copy;
    $log->Set
    (
        'word_count' => 10,
        'x_cmd'      => 255,
        'max_buff'   => 4356,
        'max_mpx'    => 2,
        'pass_len'   => length($pass)+1,
        'bcc_len'    => length($data),
        'request'    => $data,
        'sess_key'   => $self->SessionID,
    );
    
    my $ses = $STSession->copy;
    my $smb = $STSMB->copy;
    $smb->Set
    (
        'command'       => SMB_COM_SESSION_SETUP_ANDX,
        'flags1'        => 0x18,
        'flags2'        => 0x2001,
        'multiplex_id'  => $self->MultiplexID,
        'request'       => $log->Fetch,
    );
    
    $ses->Set('type' => 0, 'flags' => 0, 'request' => $smb->Fetch);
    $sock->Send($ses->Fetch);
    my $res = $self->SMBRecv();
    
    if (! $res) {
        $self->Error('Session setup failed due to null response');
        return;
    }
    
    my $ses_res = $STSession->copy;
    $ses_res->Fill($res);

    my $smb_res = $STSMB->copy;
    $smb_res->Fill($ses_res->Get('request'));
    $smb_res->Set('request' => substr($ses_res->Get('request'), $smb_res->Length));

    if ($smb_res->Get('error_class') != 0) {
        $self->Error('Session setup returned NT status '.$smb_res->Get('error_class'));
        return;
    }

    if ($smb_res->Get('command') != SMB_COM_SESSION_SETUP_ANDX) {
        $self->Error('Session setup returned command '.$smb_res->Get('command'));
        return;
    }

    my $log_res = $STSetupXRes->copy;
    $log_res->Fill($smb_res->Get('request'));

    if ($log_res->Get('action') == 1 || $user eq '') {
        $self->AuthUser("NULL");
    } else {
        $self->AuthUser($user);
    }

    $self->AuthUserID($smb_res->Get('user_id'));
    
    return $log_res; 
}

sub SMBSessionSetupNTLM {
    my $self = shift;
    my $user = @_ ? shift : "";
    my $pass = @_ ? shift : "";
    my $wdom = @_ ? shift : "";  
    my $sock = $self->Socket;
    
    return if $self->Error;
    
    # Only supports NTLMv1 right now
    
    my $lmh = length($pass) ? $self->CryptLM($pass, $self->ChallengeKey) : '';
    my $nth = length($pass) ? $self->CryptNT($pass, $self->ChallengeKey) : '';
    my $pwl = length($lmh);
    
    my $data = $lmh. $nth.
               $user . "\x00".
               $wdom . "\x00".
               $self->NativeOS."\x00".
               $self->NativeLM."\x00";
    
    my $log = $STSetupXNT->copy;
    $log->Set
    (
        'word_count' => 13,
        'x_cmd'      => 255,
        'max_buff'   => 17408,
        'max_mpx'    => 62880,
        'pass_len_lm'  => $pwl,
        'pass_len_nt'  => $pwl,
        'bcc_len'    => length($data),
        'request'    => $data,
        'sess_key'   => $self->SessionID,        
    );
    
    my $ses = $STSession->copy;
    my $smb = $STSMB->copy;
    $smb->Set
    (
        'command'       => SMB_COM_SESSION_SETUP_ANDX,
        'flags1'        => 0x18,
        'flags2'        => 0x2001,
        'multiplex_id'  => $self->MultiplexID,
        'request'       => $log->Fetch,
    );
    
    $ses->Set('type' => 0, 'flags' => 0, 'request' => $smb->Fetch);
    $sock->Send($ses->Fetch);
    my $res = $self->SMBRecv();
    
    if (! $res) {
        $self->Error('Session setup failed due to null response');
        return;
    }
    
    my $ses_res = $STSession->copy;
    $ses_res->Fill($res);

    my $smb_res = $STSMB->copy;
    $smb_res->Fill($ses_res->Get('request'));
    $smb_res->Set('request' => substr($ses_res->Get('request'), $smb_res->Length));

    if ($smb_res->Get('error_class') != 0) {
        $self->Error('Session setup returned NT status '.$smb_res->Get('error_class'));
        return;
    }

    if ($smb_res->Get('command') != SMB_COM_SESSION_SETUP_ANDX) {
        $self->Error('Session setup returned command '.$smb_res->Get('command'));
        return;
    }
    
    my $log_res = $STSetupXRes->copy;
    $log_res->Fill($smb_res->Get('request'));

    if ($log_res->Get('action') == 1 || $user eq '') {
        $self->AuthUser("NULL");
    } else {
        $self->AuthUser($user);
    }
    
    $self->AuthUserID($smb_res->Get('user_id'));
    
    return $log_res;        
}


sub SMBTConnect {
    my $self = shift;
    my $share = @_ ? shift : "\\\\127.0.0.1\\IPC\$";
    my $pass  = @_ ? shift : '';
    my $sock = $self->Socket;
    
    return if $self->Error;
    

    my $data = $pass  ."\x00".
               $share ."\x00".
               "?????"."\x00";
    
    my $log = $STTConnectX->copy;
    $log->Set
    (
        'word_count' => 4,
        'x_cmd'      => 255,
        'bcc_len'    => length($data),
        'request'    => $data,
    );

    $log->Set('pass_len' => length($pass) + 1);
    
    my $ses = $STSession->copy;
    my $smb = $STSMB->copy;
    $smb->Set
    (
        'command'       => SMB_COM_TREE_CONNECT_ANDX,
        'flags1'        => 0x18,
        'flags2'        => 0x2001,
        'multiplex_id'  => $self->MultiplexID,
        'user_id'       => $self->AuthUserID,
        'request'       => $log->Fetch,
    );
    
    $ses->Set('type' => 0, 'flags' => 0, 'request' => $smb->Fetch);
    $sock->Send($ses->Fetch);
    my $res = $self->SMBRecv();
    
    if (! $res) {
        $self->Error('Tree connect failed due to null response');
        return;
    }
    
    my $ses_res = $STSession->copy;
    $ses_res->Fill($res);

    my $smb_res = $STSMB->copy;
    $smb_res->Fill($ses_res->Get('request'));
    $smb_res->Set('request' => substr($ses_res->Get('request'), $smb_res->Length));

    if ($smb_res->Get('error_class') != 0) {
        $self->Error('Tree connect returned NT status '.$smb_res->Get('error_class'));
        return;
    }

    if ($smb_res->Get('command') != SMB_COM_TREE_CONNECT_ANDX) {
        $self->Error('Tree connect returned command '.$smb_res->Get('command'));
        return;
    }
    
    my $log_res = $STTConnectXRes->copy;
    $log_res->Fill($smb_res->Get('request'));
    
    $self->TreeID($share, $smb_res->Get('tree_id'));
    $self->LastTreeID($smb_res->Get('tree_id'));  
    return $log_res;       
}

sub SMBTrans {
    my $self = shift;
    my $targ = @_ ? shift : '';
    my $parm = @_ ? shift : '';
    my $data = @_ ? shift : '';
    my $setup_count = @_ ? shift : 0;
    my $setup_data  = @_ ? shift : '';
    my $sock = $self->Socket;
    
    return if $self->Error;

    my $contents = $targ . "\x00". $parm . $data;

    my $data_count  = length($data);
    my $param_count = length($parm);

    my $offset_base = $STSMB->Length + $STTrans->Length + length($targ) + length($setup_data);
    my $param_offset = $offset_base;
    my $data_offset = $param_offset + length($parm);

    my $log = $STTrans->copy;
    $log->Set
    (
        'word_count'      => 14 + $setup_count,
        'param_count_tot' => $param_count,
        'data_count_tot'  => $data_count,
        'param_count_max' => $param_count,
        'data_count_max'  => 65535,
        'param_count'     => $param_count,
        'param_offset'    => $param_offset,        
        'data_count'      => $data_count,
        'data_offset'     => $data_offset,
        'setup_count'     => $setup_count,
        'setup_data'      => $setup_data,
        'bcc_len'         => length($contents),
        'request'         => $contents,
    );
    
    my $ses = $STSession->copy;
    my $smb = $STSMB->copy;
    
    $smb->Set
    (
        'command'       => SMB_COM_TRANSACTION,
        'flags1'        => 0x18,
        'flags2'        => 0x2001,
        'tree_id'       => $self->LastTreeID,
        'multiplex_id'  => $self->MultiplexID,
        'user_id'       => $self->AuthUserID,
        'request'       => $log->Fetch,
    );
    
    $ses->Set('type' => 0, 'flags' => 0, 'request' => $smb->Fetch);
    $sock->Send($ses->Fetch);
    my $res = $self->SMBRecv();
    
    if (! $res) {
        $self->Error('Transaction failed due to null response');
        return;
    }
    
    my $ses_res = $STSession->copy;
    $ses_res->Fill($res);

    my $smb_res = $STSMB->copy;
    $smb_res->Fill($ses_res->Get('request'));
    $smb_res->Set('request' => substr($ses_res->Get('request'), $smb_res->Length));

    if ($smb_res->Get('error_class') != 0) {
        $self->Error('Transaction returned NT status '.$smb_res->Get('error_class'));
        return;
    }

    if ($smb_res->Get('command') != SMB_COM_TRANSACTION) {
        $self->Error('Transaction returned command '.$smb_res->Get('command'));
        return;
    }
    
    
}


# XXX - Written to use with lsarpc pipe
sub SMBCreate {
    my $self = shift;
    my $file = shift;
    my $sock = $self->Socket;
    
    return if $self->Error;

    my $log = $STCreateX->copy;
    $log->Set
    (
        'word_count'    => 24,
        'x_cmd'         => 255,
        'x_off'         => 0,
        'filename_len'  => length($file),
        'create_flags'  => 0x16,
        'access_mask'   => 0x2019f,
        'share_access'  => 3,
        'create_opts'   => 0x40,
        'impersonation' => 2,
        'disposition'   => 1,
        'sec_flags'     => 3,
        'bcc_len'       => length($file)+1,
        'request'       => $file."\x00",
    );
    
    my $ses = $STSession->copy;
    my $smb = $STSMB->copy;
    $smb->Set
    (
        'command'       => 0xA2,
        'flags1'        => 0x18,
        'flags2'        => 0x2001,
        'tree_id'       => $self->LastTreeID,
        'multiplex_id'  => $self->MultiplexID,
        'user_id'       => $self->AuthUserID,
        'request'       => $log->Fetch,
    );
    
    $ses->Set('type' => 0, 'flags' => 0, 'request' => $smb->Fetch);
    $sock->Send($ses->Fetch);
    my $res = $self->SMBRecv();
    
    if (! $res) {
        $self->Error('Create failed due to null response');
        return;
    }
    
    my $ses_res = $STSession->copy;
    $ses_res->Fill($res);

    my $smb_res = $STSMB->copy;
    $smb_res->Fill($ses_res->Get('request'));
    $smb_res->Set('request' => substr($ses_res->Get('request'), $smb_res->Length));

    if ($smb_res->Get('error_class') != 0) {
        $self->Error('Create returned NT status '.$smb_res->Get('error_class'));
        return;
    }

    if ($smb_res->Get('command') != 0xA2) {
        $self->Error('Create returned command '.$smb_res->Get('command'));
        return;
    }
    
    my $log_res = $STCreateXRes->copy;
    $log_res->Fill($smb_res->Get('request'));  
    $self->LastFileID($log_res->Get('fid'));

    return $log_res;       
}


sub SMBLanMan_NetServerEnum2 {
    my $self = shift;
    my $type = @_ ? shift : 0xffffffff;
    my $wdom = @_ ? shift : 'WORKGROUP';
    my $res;
    
    my $targ = '\PIPE\LANMAN';

    my $parm = pack('v', 104).
            "WrLehDz"."\x00".
            "B16BBDz"."\x00".
            pack('v', 1).
            pack('v', 0xffff).
            pack('V', $type).
            "$wdom\x00";

    my $res = $self->SMBTrans($targ, $parm, '');
    return $res;
}

sub SMBTransNP {
    my $self = shift;
    my $fid  = @_ ? shift : $self->LastFileID;
    my $data = @_ ? shift : '';
    my $res;

    my $setup_count = 2;
    my $setup_data  = pack('vv', 0x26, $fid);
    my $targ = "\\PIPE\\";

    my $res = $self->SMBTrans($targ, '', $data, $setup_count, $setup_data);
    return $res;

}



# This has only been tested in conjunction with \lsarpc
sub SMBWrite {
    my $self = shift;
    my $fid  = @_ ? shift : $self->LastFileID;
    my $off  = @_ ? shift : 0;
    my $data = shift;
    my $sock = $self->Socket;
    
    return if $self->Error;

    my $data_len = length($data);
    my $data_offset = $STSMB->Length + $STWriteX->Length;

    my $log = $STWriteX->copy;
    $log->Set
    (
        'word_count'    => 14,
        'x_cmd'         => 255,
        'reserved1'     => 0,
        'x_off'         => 0,
        'fid'           => $fid,
        'offset'        => $off,
        'reserved2'     => 0xffffffff,
        'write_mode'    => 8,
        'remaining'     => $data_len,
        'data_len_high' => 0,
        'data_len_low'  => $data_len,
        'data_offset'   => $data_offset,
        'bcc_len'       => $data_len,
        'request'       => $data,
    );
    
    my $ses = $STSession->copy;
    my $smb = $STSMB->copy;
    $smb->Set
    (
        'command'       => 0x2F,
        'flags1'        => 0x18,
        'flags2'        => 0x2001,
        'tree_id'       => $self->LastTreeID,
        'multiplex_id'  => $self->MultiplexID,
        'user_id'       => $self->AuthUserID,
        'request'       => $log->Fetch,
    );
    
    $ses->Set('type' => 0, 'flags' => 0, 'request' => $smb->Fetch);
    $sock->Send($ses->Fetch);
    my $res = $self->SMBRecv();
    
    if (! $res) {
        $self->Error('Create failed due to null response');
        return;
    }
    
    my $ses_res = $STSession->copy;
    $ses_res->Fill($res);

    my $smb_res = $STSMB->copy;
    $smb_res->Fill($ses_res->Get('request'));
    $smb_res->Set('request' => substr($ses_res->Get('request'), $smb_res->Length));

    if ($smb_res->Get('error_class') != 0) {
        $self->Error('Write returned NT status '.$smb_res->Get('error_class'));
        return;
    }

    if ($smb_res->Get('command') != 0x2F) {
        $self->Error('Write returned command '.$smb_res->Get('command'));
        return;
    }

    my $log_res = $STWriteXRes->copy;
    $log_res->Fill($smb_res->Get('request'));  
    return $log_res;          
}


############################################
# This is straight from Authen::NTLM::DES  #
############################################

package SMBDES;

my ($loop, $loop2);
$loop = 0;
$loop2 = 0;

my $perm1 = [57, 49, 41, 33, 25, 17, 9,
             1, 58, 50, 42, 34, 26, 18,
	     10, 2, 59, 51, 43, 35, 27,
	     19, 11, 3, 60, 52, 44, 36,
	     63, 55, 47, 39, 31, 23, 15,
	     7, 62, 54, 46, 38, 30, 22,
	     14, 6, 61, 53, 45, 37, 29,
	     21, 13, 5, 28, 20, 12, 4];
my $perm2 = [14, 17, 11, 24, 1, 5,
             3, 28, 15, 6, 21, 10,
	     23, 19, 12, 4, 26, 8,
	     16, 7, 27, 20, 13, 2,
	     41, 52, 31, 37, 47, 55,
	     30, 40, 51, 45, 33, 48,
	     44, 49, 39, 56, 34, 53,
	     46, 42, 50, 36, 29, 32];
my $perm3 = [58, 50, 42, 34, 26, 18, 10, 2,
             60, 52, 44, 36, 28, 20, 12, 4,
	     62, 54, 46, 38, 30, 22, 14, 6,
	     64, 56, 48, 40, 32, 24, 16, 8,
	     57, 49, 41, 33, 25, 17, 9, 1,
	     59, 51, 43, 35, 27, 19, 11, 3,
	     61, 53, 45, 37, 29, 21, 13, 5,
	     63, 55, 47, 39, 31, 23, 15, 7];
my $perm4 = [32, 1, 2, 3, 4, 5,
             4, 5, 6, 7, 8, 9,
	     8, 9, 10, 11, 12, 13,
	     12, 13, 14, 15, 16, 17,
	     16, 17, 18, 19, 20, 21,
	     20, 21, 22, 23, 24, 25,
	     24, 25, 26, 27, 28, 29,
	     28, 29, 30, 31, 32, 1];
my $perm5 = [16, 7, 20, 21, 29, 12, 28, 17,
             1, 15, 23, 26, 5, 18, 31, 10,
	     2, 8, 24, 14, 32, 27, 3, 9,
	     19, 13, 30, 6, 22, 11, 4, 25];
my $perm6 = [40, 8, 48, 16, 56, 24, 64, 32,
             39, 7, 47, 15, 55, 23, 63, 31,
	     38, 6, 46, 14, 54, 22, 62, 30,
	     37, 5, 45, 13, 53, 21, 61, 29,
	     36, 4, 44, 12, 52, 20, 60, 28,
	     35, 3, 43, 11, 51, 19, 59, 27,
	     34, 2, 42, 10, 50, 18, 58, 26,
	     33, 1, 41,  9, 49, 17, 57, 25];
my $sc = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
my $sbox = [
[
[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
],
[
[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
],
[
[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
],
[
[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
],
[
[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
],
[
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
],
[
[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
],
[
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
]
];

sub E_P16
{
  my ($p14) = @_;
  my $sp8 = [0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25];

  my $p7 = substr($p14, 0, 7);
  my $p16 = smbhash($sp8, $p7);
  $p7 = substr($p14, 7, 7);
  $p16 .= smbhash($sp8, $p7);
  return $p16;
}

sub E_P24
{
  my ($p21, $c8_str) = @_;
  my @c8 = map {ord($_)} split(//, $c8_str);
  my $p24 = smbhash(\@c8, substr($p21, 0, 7));
  $p24 .= smbhash(\@c8, substr($p21, 7, 7));
  $p24 .= smbhash(\@c8, substr($p21, 14, 7));
}

sub permute
{
  my ($out, $in, $p, $n) = @_;
  my $i;

  foreach $i (0..($n-1))
  {
    $out->[$i] = $in->[$p->[$i]-1];
  }
}

sub lshift
{
  my ($d, $count, $n) = @_;
  my (@out, $i);

  foreach $i (0..($n-1))
  {
    $out[$i] = $d->[($i+$count)%$n];
  }
  foreach $i (0..($n-1))
  {
    $d->[$i] = $out[$i];
  }
}

sub xor
{
  my ($out, $in1, $in2, $n) = @_;
  my $i;

  foreach $i (0..($n-1))
  {
    $out->[$i] = $in1->[$i]^$in2->[$i];
  }
}

sub dohash
{
  my ($out, $in, $key) = @_;
  my ($i, $j, $k, @pk1, @c, @d, @cd,
      @ki, @pd1, @l, @r, @rl);

  &permute(\@pk1, $key, $perm1, 56);

  foreach $i (0..27)
  {
    $c[$i] = $pk1[$i];
    $d[$i] = $pk1[$i+28];
  }
  foreach $i (0..15)
  {
    my @array;
    &lshift(\@c, $sc->[$i], 28);
    &lshift(\@d, $sc->[$i], 28);
    @cd = (@c, @d);
    &permute(\@array, \@cd, $perm2, 48);
    $ki[$i] = \@array;
  }
  &permute(\@pd1, $in, $perm3, 64);

  foreach $j (0..31)
  {
    $l[$j] = $pd1[$j];
    $r[$j] = $pd1[$j+32];
  }

  foreach $i (0..15)
  {
    my (@er, @erk, @b, @cb, @pcb, @r2);
    permute(\@er, \@r, $perm4, 48);
    &xor(\@erk, \@er, $ki[$i], 48);
    foreach $j (0..7)
    {
      foreach $k (0..5)
      {
	$b[$j][$k] = $erk[$j*6+$k];
      }
    }
    foreach $j (0..7)
    {
      my ($m, $n);
      $m = ($b[$j][0]<<1) | $b[$j][5];
      $n = ($b[$j][1]<<3) | ($b[$j][2]<<2) | ($b[$j][3]<<1) | $b[$j][4];
      foreach $k (0..3)
      {
	$b[$j][$k] = ($sbox->[$j][$m][$n] & (1<<(3-$k)))? 1: 0;
      }
    }
    foreach $j (0..7)
    {
      foreach $k (0..3)
      {
	$cb[$j*4+$k] = $b[$j][$k];
      }
    }
    &permute(\@pcb, \@cb, $perm5, 32);
    &xor(\@r2, \@l, \@pcb, 32);
    foreach $j (0..31)
    {
      $l[$j] = $r[$j];
      $r[$j] = $r2[$j];
    }
  }
  @rl = (@r, @l);
  &permute($out, \@rl, $perm6, 64);
}

sub str_to_key
{
  my ($str) = @_;
  my $i;
  my @key;
  my $out;
  my @str = map {ord($_)} split(//, $str);
  $key[0] = $str[0]>>1;
  $key[1] = (($str[0]&0x01)<<6) | ($str[1]>>2);
  $key[2] = (($str[1]&0x03)<<5) | ($str[2]>>3);
  $key[3] = (($str[2]&0x07)<<4) | ($str[3]>>4);
  $key[4] = (($str[3]&0x0f)<<3) | ($str[4]>>5);
  $key[5] = (($str[4]&0x1f)<<2) | ($str[5]>>6);
  $key[6] = (($str[5]&0x3f)<<1) | ($str[6]>>7);
  $key[7] = $str[6]&0x7f;
  foreach $i (0..7)
  {
    $key[$i] = 0xff&($key[$i]<<1);
  }
  return \@key;
}

sub smbhash
{
  my ($in, $key) = @_;

  my $key2 = &str_to_key($key);
  my ($i, $div, $mod, @in, @outb, @inb, @keyb, @out);
  foreach $i (0..63)
  {
    $div = int($i/8); $mod = $i%8;
    $inb[$i] = ($in->[$div] & (1<<(7-($mod))))? 1: 0;
    $keyb[$i] = ($key2->[$div] & (1<<(7-($mod))))? 1: 0;
    $outb[$i] = 0;
  }
  &dohash(\@outb, \@inb, \@keyb);
  foreach $i (0..7)
  {
    $out[$i] = 0;
  }
  foreach $i (0..63)
  {
    $out[int($i/8)] |= (1<<(7-($i%8))) if ($outb[$i]);
  }
  my $out = pack("C8", @out);
  return $out;
}

############################################
# This is straight from Authen::NTLM::MD4  #
############################################
package SMBMD4;

my ($A, $B, $C, $D);
my (@X, $M);

sub MD4
{
  my ($in) = @_;

  my ($i, $pos);
  my $len = length($in);
  my $b = $len * 8;
  $in .= "\0"x128;
  $A = 0x67452301;
  $B = 0xefcdab89;
  $C = 0x98badcfe;
  $D = 0x10325476;
  $pos = 0;
  while ($len > 64)
  {
    &copy64(substr($in, $pos, 64));
    &mdfour64;
    $pos += 64;
    $len -= 64;
  }
  my $buf = substr($in, $pos, $len);
  $buf .= sprintf "%c", 0x80;
  if ($len <= 55)
  {
    $buf .= "\0"x(55-$len);
    $buf .= pack("V", $b);
    $buf .= "\0"x4;
    &copy64($buf);
    &mdfour64;
  }
  else
  {
    $buf .= "\0"x(120-$len);
    $buf .= pack("V", $b);
    $buf .= "\0"x4;
    &copy64(substr($buf, 0, 64));
    &mdfour64;
    &copy64(substr($buf, 64, 64));
    &mdfour64;
  }
  my $out = pack("VVVV", $A, $B, $C, $D);
  return $out;
}

sub F
{
  my ($X, $Y, $Z) = @_;
  my $res = ($X&$Y) | ((~$X)&$Z);
  return $res;
}

sub G
{
  my ($X, $Y, $Z) = @_;

  return ($X&$Y) | ($X&$Z) | ($Y&$Z);
}

sub H
{
  my ($X, $Y, $Z) = @_;

  return $X^$Y^$Z;
}

sub lshift
{
  my ($x, $s) = @_;

  $x &= 0xffffffff;
  return (($x<<$s)&0xffffffff) | ($x>>(32-$s));
}

sub ROUND1
{
  my ($a, $b, $c, $d, $k, $s) = @_;
  my $e = &add($a, &F($b, $c, $d), $X[$k]);
  return &lshift($e, $s);
}

sub ROUND2
{
  my ($a, $b, $c, $d, $k, $s) = @_;

  my $e = &add($a, &G($b, $c, $d), $X[$k], 0x5a827999);
  return &lshift($e, $s);
}

sub ROUND3
{
  my ($a, $b, $c, $d, $k, $s) = @_;

  my $e = &add($a, &H($b, $c, $d), $X[$k], 0x6ed9eba1);
  return &lshift($e, $s);
}

sub mdfour64
{
  my ($i, $AA, $BB, $CC, $DD);
  @X = unpack("N16", $M);
  $AA = $A;
  $BB = $B;
  $CC = $C;
  $DD = $D;

  $A = &ROUND1($A,$B,$C,$D, 0, 3); $D = &ROUND1($D,$A,$B,$C, 1, 7);
  $C = &ROUND1($C,$D,$A,$B, 2,11); $B = &ROUND1($B,$C,$D,$A, 3,19);
  $A = &ROUND1($A,$B,$C,$D, 4, 3); $D = &ROUND1($D,$A,$B,$C, 5, 7);
  $C = &ROUND1($C,$D,$A,$B, 6,11); $B = &ROUND1($B,$C,$D,$A, 7,19);
  $A = &ROUND1($A,$B,$C,$D, 8, 3); $D = &ROUND1($D,$A,$B,$C, 9, 7);
  $C = &ROUND1($C,$D,$A,$B,10,11); $B = &ROUND1($B,$C,$D,$A,11,19);
  $A = &ROUND1($A,$B,$C,$D,12, 3); $D = &ROUND1($D,$A,$B,$C,13, 7);
  $C = &ROUND1($C,$D,$A,$B,14,11); $B = &ROUND1($B,$C,$D,$A,15,19);

  $A = &ROUND2($A,$B,$C,$D, 0, 3); $D = &ROUND2($D,$A,$B,$C, 4, 5);
  $C = &ROUND2($C,$D,$A,$B, 8, 9); $B = &ROUND2($B,$C,$D,$A,12,13);
  $A = &ROUND2($A,$B,$C,$D, 1, 3); $D = &ROUND2($D,$A,$B,$C, 5, 5);
  $C = &ROUND2($C,$D,$A,$B, 9, 9); $B = &ROUND2($B,$C,$D,$A,13,13);
  $A = &ROUND2($A,$B,$C,$D, 2, 3); $D = &ROUND2($D,$A,$B,$C, 6, 5);
  $C = &ROUND2($C,$D,$A,$B,10, 9); $B = &ROUND2($B,$C,$D,$A,14,13);
  $A = &ROUND2($A,$B,$C,$D, 3, 3); $D = &ROUND2($D,$A,$B,$C, 7, 5);
  $C = &ROUND2($C,$D,$A,$B,11, 9); $B = &ROUND2($B,$C,$D,$A,15,13);

  $A = &ROUND3($A,$B,$C,$D, 0, 3); $D = &ROUND3($D,$A,$B,$C, 8, 9);
  $C = &ROUND3($C,$D,$A,$B, 4,11); $B = &ROUND3($B,$C,$D,$A,12,15);
  $A = &ROUND3($A,$B,$C,$D, 2, 3); $D = &ROUND3($D,$A,$B,$C,10, 9);
  $C = &ROUND3($C,$D,$A,$B, 6,11); $B = &ROUND3($B,$C,$D,$A,14,15);
  $A = &ROUND3($A,$B,$C,$D, 1, 3); $D = &ROUND3($D,$A,$B,$C, 9, 9);
  $C = &ROUND3($C,$D,$A,$B, 5,11); $B = &ROUND3($B,$C,$D,$A,13,15);
  $A = &ROUND3($A,$B,$C,$D, 3, 3); $D = &ROUND3($D,$A,$B,$C,11, 9);
  $C = &ROUND3($C,$D,$A,$B, 7,11); $B = &ROUND3($B,$C,$D,$A,15,15);

  $A = &add($A, $AA); $B = &add($B, $BB);
  $C = &add($C, $CC); $D = &add($D, $DD);
  $A &= 0xffffffff; $B &= 0xffffffff;
  $C &= 0xffffffff; $D &= 0xffffffff;
  map {$_ = 0} @X;
}

sub copy64
{
  my ($in) = @_;

  $M = pack("V16", unpack("N16", $in));
}

# see note at top of this file about this function
sub add
{
  my (@nums) = @_;
  my ($r_low, $r_high, $n_low, $n_high);
  my $num;
  $r_low = $r_high = 0;
  foreach $num (@nums)
  {
    $n_low = $num & 0xffff;
    $n_high = ($num&0xffff0000)>>16;
    $r_low += $n_low;
    ($r_low&0xf0000) && $r_high++;
    $r_low &= 0xffff;
    $r_high += $n_high;
    $r_high &= 0xffff;
  }
  return ($r_high<<16)|$r_low;
}


1;

__END__
