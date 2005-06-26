package Pex::BEServerRPC;
use strict;

use constant REG_SZ => 1;
use constant REG_EXPAND_SZ => 2;
use constant REG_BINARY => 3;

use constant HKEY_CLASSES_ROOT => 0x80000000;
use constant HKEY_CURRENT_USER => 0x80000001;
use constant HKEY_LOCAL_MACHINE => 0x80000002;
use constant HKEY_USERS => 0x80000003;
use constant HKEY_PERFORMANCE_DATA => 0x80000004;
use constant HKEY_CURRENT_CONFIG => 0x80000005;
use constant HKEY_DYN_DATA => 0x80000006;


##
# RPC Procedure 4
##
sub RegRead {
	my $subkey = Unicode( shift() . "\x00" );
	my $subval = Unicode( shift() . "\x00" );
	my $hive   = @_ ? shift() : HKEY_LOCAL_MACHINE;
	
	my $data = 
		# Encode the subkey path
		pack('VVV',
			(length($subkey)/2),
			0,
			(length($subkey)/2),
		). DwordPad($subkey).
		
		# Encode the subkey value
		pack('VVV',
			(length($subval)/2),
			0,
			(length($subval)/2),
		). DwordPad($subval).
		
		# The registry key type
		pack('V', REG_SZ).
		
		# The size of the output buffer
		pack('V', 1024).
		
		# The size of the input buffer
		pack('V', 0).
		
		# The length value of the hive
		pack('V', 4).
		
		# The actual hive data
		pack('VV', 4, $hive);

	return $data;
}

##
# RPC Procedure 7
##
sub RegEnum {
	my $subkey = Unicode( shift() . "\x00" );
	my $hive   = @_ ? shift() : HKEY_LOCAL_MACHINE;
	
	my $data = 
		# Encode the subkey path
		pack('VVV',
			(length($subkey)/2),
			0,
			(length($subkey)/2),
		). DwordPad($subkey).

		# The size of the output buffer
		pack('V', 4096).
		
		# The size of the input buffer
		pack('V', 0).
		
		# The length value of the hive
		pack('V', 4).
		
		# The actual hive data
		pack('VV', 4, $hive);

	return $data;
}

##
# RPC Procedure 5
##
sub RegWrite {
	my $subkey = Unicode( shift() . "\x00" );
	my $subval = Unicode( shift() . "\x00" );
	my $write  = Unicode( shift() );
	my $hive   = @_ ? shift() : HKEY_LOCAL_MACHINE;
	
	my $data = 
		# Encode the subkey path
		pack('VVV',
			(length($subkey)/2),
			0,
			(length($subkey)/2),
		). DwordPad($subkey).
		
		# Encode the subkey value
		pack('VVV',
			(length($subval)/2),
			0,
			(length($subval)/2),
		). DwordPad($subval).
		
		# The registry key type
		pack('V', REG_SZ).
		
		# The size of the output buffer
		pack('V', length($write)).
		
		# The size of the input buffer
		pack('V', length($write)).
		
		# The actual data to write to the key
		DwordPad($write).
		
		# The length value of the hive
		pack('V', 4).
		
		# The actual hive data
		pack('VV', 4, $hive);

	return $data;
}

sub DwordPad {
	my $data = shift;
	while (length($data) % 4 != 0) { $data .= "\x00" }
	return $data;
}

sub Unicode {
	return pack('v*', unpack('C*', shift()));
}

1;
