#include "../fs.h"

/*
 * File channel direct I/O handler for reading/writing files
 */
DWORD file_channel_dio_handler(Channel *channel, ChannelBuffer *buffer,
		FileContext *ctx, ChannelDioMode mode, PUCHAR chunk, ULONG length,
		PULONG bytesXfered)
{
	LONG localBytesXfered = 0;
	DWORD res = ERROR_SUCCESS;

	if (bytesXfered)
		*bytesXfered = 0;

	switch (mode)
	{
		case CHANNEL_DIO_MODE_READ:
			if ((localBytesXfered = fread(chunk, 1, length, ctx->fd)) <= 0)
			{
				localBytesXfered = 0;
				res              = GetLastError();
			}
			break;
		case CHANNEL_DIO_MODE_WRITE:
			if ((localBytesXfered = fwrite(chunk, 1, length, ctx->fd)) <= 0)
			{
				localBytesXfered = 0;
				res              = GetLastError();
			}
			break;
		// On close, close the file descriptor and free the context
		case CHANNEL_DIO_MODE_CLOSE:
			fclose(ctx->fd);
			free(ctx);
			break;
		default:
			break;
	}

	if (bytesXfered)
		*bytesXfered = localBytesXfered;

	return res;
}

/*
 * Allocate a new channel that is associated with a local file on disk
 * and send the new channel identifier response to the requestor
 */
DWORD request_fs_file_open(Remote *remote, Packet *packet)
{
	Packet *response = NULL;
	PCHAR filePath, modeString, channelType;
	DWORD res = ERROR_SUCCESS;
	Channel *newChannel;
	FileContext *ctx;
	DWORD mode;

	do
	{
		// If this is not an FS channel open, ignore it.
		if ((!(channelType = packet_get_tlv_value_string(packet,
				TLV_TYPE_CHANNEL_TYPE))) ||
		    (strcmp(channelType, "fs")))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Allocate a response
		response = packet_create_response(packet);

		// Check the response allocation & allocate a un-connected
		// channel
		if ((!response) ||
		    (!(newChannel = channel_create(0))) ||
		    (!(ctx = (FileContext *)malloc(sizeof(FileContext)))))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the file path and the mode
		filePath = packet_get_tlv_value_string(packet, TLV_TYPE_FS_PATH);
		mode     = packet_get_tlv_value_uint(packet, TLV_TYPE_FS_MODE);

		// Determine the actual mode
		switch (mode)
		{
			case FILE_MODE_READ:      modeString = "rb";  break;
			case FILE_MODE_WRITE:     modeString = "wb";  break;
			case FILE_MODE_READWRITE: modeString = "rwb"; break;
		}

		// Invalid file?
		if ((!filePath) ||
		    (!(ctx->fd = fopen(filePath, modeString))))
		{
			res = (filePath) ? ERROR_FILE_NOT_FOUND : GetLastError();
			break;
		}

		// Set the direct I/O handler for this channel to the file 
		// channel direct I/O handler.
		channel_set_local_io_handler(newChannel, ctx,
				(DirectIoHandler)file_channel_dio_handler);

		// Add the channel identifier to the response
		packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, 
				channel_get_id(newChannel));

	} while (0);

	// Transmit the packet if it's valid
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

		packet_transmit(remote, response, NULL);
	}

	// Clean up on failure
	if (res != ERROR_SUCCESS)
	{
		if (newChannel)
			channel_destroy(newChannel);
		if (ctx)
			free(ctx);
	}

	return res;
}
