#include "../fs.h"

/*
 * Opens a file as a channel and calls the completion routine upon success
 */
DWORD file_open(Remote *remote, LPCSTR file, DWORD mode, 
		ChannelCompletionRoutine *complete)
{
	DWORD res = ERROR_SUCCESS;
	PCHAR method = "core_channel_open";
	Tlv addend[4];

	mode = htonl(mode);

	// Transmit method=machine_fs_file_open, fs_path=file, fs_mode=mode
	addend[0].header.length = strlen(method) + 1;
	addend[0].header.type   = TLV_TYPE_METHOD;
	addend[0].buffer        = (PUCHAR)method;
	addend[1].header.length = strlen(file) + 1;
	addend[1].header.type   = TLV_TYPE_FS_PATH;
	addend[1].buffer        = (PUCHAR)file;
	addend[2].header.length = sizeof(DWORD);
	addend[2].header.type   = TLV_TYPE_FS_MODE;
	addend[2].buffer        = (PUCHAR)&mode;

	// Lastly, indicate to core_channel_open that this is an extended channel
	// open.
	addend[3].header.length = 3;
	addend[3].header.type   = TLV_TYPE_CHANNEL_TYPE;
	addend[3].buffer        = (PUCHAR)"fs";

	// Try to open the channel with the given addend
	return channel_open(remote, addend, 4, complete);
}
