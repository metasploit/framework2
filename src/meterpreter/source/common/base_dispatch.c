#include "common.h"

/*
 * core_channel_open
 * -----------------
 *
 * Opens a channel with the remote endpoint.  The response handler for this
 * request will establish the relationship on the other side.
 *
 * opt: TLV_TYPE_CHANNEL_TYPE 
 *      The channel type to allocate.  If set, the function returns, allowing
 *      a further up extension handler to allocate the channel.
 */
DWORD remote_request_core_channel_open(Remote *remote, Packet *packet)
{
	Packet *response;
	DWORD res = ERROR_SUCCESS;
	Channel *newChannel;
	PCHAR channelType;

	do
	{
		// If the channel open request had a specific channel type
		if ((channelType = packet_get_tlv_value_string(packet, 
				TLV_TYPE_CHANNEL_TYPE)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Allocate a response
		response = packet_create_response(packet);
		
		// Did the response allocation fail?
		if ((!response) ||
		    (!(newChannel = channel_create(0))))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the new channel identifier to the response
		if ((res = packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID,
				channel_get_id(newChannel))) != ERROR_SUCCESS)
			break;

		// Transmit the response
		res = packet_transmit(remote, response, NULL);

	} while (0);

	return res;
}

/*
 * core_channel_open (response)
 * -----------------
 *
 * Handles the response to a request to open a channel.
 *
 * This function takes the supplied channel identifier and creates a
 * channel list entry with it.
 *
 * req: TLV_TYPE_CHANNEL_ID -- The allocated channel identifier
 */
DWORD remote_response_core_channel_open(Remote *remote, Packet *packet)
{
	DWORD res = ERROR_SUCCESS, channelId;
	Channel *newChannel;

	do
	{
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);
		
		// DId the request fail?
		if (!channelId)
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Create a local instance of the channel with the supplied identifier
		if (!(newChannel = channel_create(channelId)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

	} while (0);

	return res;
}

/*
 * core_channel_write
 * -----------------
 *
 * Write data from a channel into the local output buffer for it
 */
DWORD remote_request_core_channel_write(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS, channelId, written = 0;
	Tlv channelData;
	Channel *channel;

	do
	{
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

		// Try to locate the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Get the channel data buffer
		if ((res = packet_get_tlv(packet, TLV_TYPE_CHANNEL_DATA, &channelData)) 
				!= ERROR_SUCCESS)
			break;

		if ((res = channel_write_to_local(channel, channelData.buffer,
				channelData.header.length, &written)) != ERROR_SUCCESS)
			break;

	} while (0);

	// Transmit the acknowledgement
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);
		packet_add_tlv_uint(response, TLV_TYPE_LENGTH, written);
		packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channelId);

		res = packet_transmit(remote, response, NULL);
	}

	return res;
}

/*
 * core_channel_read
 * -----------------
 *
 * From from the local buffer and write back to the requester
 *
 * Takes TLVs:
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to read from
 * req: TLV_TYPE_LENGTH     -- The number of bytes to read
 */
DWORD remote_request_core_channel_read(Remote *remote, Packet *packet)
{
	DWORD res = ERROR_SUCCESS, bytesToRead, bytesRead, channelId;
	Packet *response = packet_create_response(packet);
	PUCHAR temporaryBuffer = NULL;
	Channel *channel = NULL;

	do
	{
		// Get the number of bytes to read
		bytesToRead = packet_get_tlv_value_uint(packet, TLV_TYPE_LENGTH);
		channelId   = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

		// Try to locate the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Allocate temporary storage
		if (!(temporaryBuffer = (PUCHAR)malloc(bytesToRead)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Read in from local
		if ((res = channel_read_from_local(channel, temporaryBuffer, bytesToRead,
				&bytesRead)) != ERROR_SUCCESS)
			break;

		// Write the buffer to the remote endpoint
		if ((res = channel_write(channel, remote, NULL, 0, temporaryBuffer, 
				bytesRead, NULL)) != ERROR_SUCCESS)
			break;

	} while (0);

	if (temporaryBuffer)
		free(temporaryBuffer);

	// Transmit the acknowledgement
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);
		packet_add_tlv_uint(response, TLV_TYPE_LENGTH, bytesRead);
		packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channelId);

		res = packet_transmit(remote, response, NULL);
	}

	return res;
}

/*
 * core_channel_close
 * ------------------
 *
 * Closes a previously opened channel.
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to close
 */
DWORD remote_request_core_channel_close(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS, channelId;
	Channel *channel = NULL;

	do
	{
		// Get the channel identifier
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

		// Try to locate the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Destroy the channel
		channel_destroy(channel);

		if (response)
			packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channelId);

	} while (0);

	// Transmit the acknowledgement
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

		res = packet_transmit(remote, response, NULL);
	}

	return res;
}

/*
 * core_channel_close (response)
 * ------------------
 *
 * Removes the local instance of the channel
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to close
 */
DWORD remote_response_core_channel_close(Remote *remote, Packet *packet)
{
	DWORD res = ERROR_SUCCESS, channelId;
	Channel *channel = NULL;

	do
	{
		// Get the channel identifier
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

		// Try to locate the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Destroy the channel
		channel_destroy(channel);

	} while (0);

	return res;
}

/*
 * core_channel_interact
 * ---------------------
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to interact with
 * req: TLV_TYPE_BOOL       -- True if interactive, false if not.
 */
DWORD remote_request_core_channel_interact(Remote *remote, Packet *packet)
{
	Channel *channel;
	DWORD channelId;
	BOOL interact;

	// Get the channel identifier
	channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);
	interact  = packet_get_tlv_value_bool(packet, TLV_TYPE_BOOL);

	// If the channel is found, set the interactive flag accordingly
	if ((channel = channel_find_by_id(channelId)))
		channel_set_interactive(channel, interact);

	return ERROR_SUCCESS;
}

/*
 * core_crypto_negotiate
 * ---------------------
 *
 * Negotiates a cryptographic session with the remote host
 *
 * req: TLV_TYPE_CIPHER_NAME       -- The cipher being selected.
 * opt: TLV_TYPE_CIPHER_PARAMETERS -- The paramters passed to the cipher for
 *                                    initialization
 */
DWORD remote_request_core_crypto_negotiate(Remote *remote, Packet *packet)
{
	LPCSTR cipherName = packet_get_tlv_value_string(packet,
			TLV_TYPE_CIPHER_NAME);
	DWORD res = ERROR_INVALID_PARAMETER;
	Packet *response = packet_create_response(packet);

	// If a cipher name was supplied, set it
	if (cipherName)
		res = remote_set_cipher(remote, cipherName, packet);

	// Transmit a response
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

		packet_transmit(remote, response, NULL);
	}

	return ERROR_SUCCESS;
}
