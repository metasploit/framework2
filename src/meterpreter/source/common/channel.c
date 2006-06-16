#include "common.h"

// List insertion and removal 
VOID channel_add_list_entry(Channel *channel);
VOID channel_remove_list_entry(Channel *channel);

// Generic buffer manipulation routines
VOID channel_set_buffer_io_handler(ChannelBuffer *buffer, LPVOID context,
		DirectIoHandler dio);
VOID channel_write_buffer(Channel *channel, ChannelBuffer *buffer, 
		PUCHAR chunk, ULONG chunkLength, PULONG bytesWritten);
VOID channel_read_buffer(Channel *channel, ChannelBuffer *buffer, 
		PUCHAR chunk, ULONG chunkLength, PULONG bytesRead);

// Channel routine duplication
ChannelCompletionRoutine *channel_duplicate_completion_routine(
		ChannelCompletionRoutine *in);

// Linked list of allocated channels
Channel *channelList = NULL;
DWORD channelIdPool  = 0;

/*
 * Create a new channel, optionally with a supplied identifier.
 *
 * If the identifier is zero, a new unique identifier is allocated.
 *
 * TODO: identifier conflicts due to being able to supply an id
 */
Channel *channel_create(DWORD identifier)
{
	Channel *channel = NULL;

	do
	{
		// Allocate storage for the channel
		if (!(channel = (Channel *)malloc(sizeof(Channel))))
			break;

		// Zero it
		memset(channel, 0, sizeof(Channel));

		// Set the channel's unique identifier
		channel->identifier  = (!identifier) ? ++channelIdPool : identifier;
		channel->interactive = FALSE;

		// Initialize the channel's local default IO handler
		// to the internal buffering methods
		channel_set_local_io_handler(channel, &channel->local,
				channel_default_io_handler);

		// Insert the channel into the list of channels
		channel_add_list_entry(channel);

	} while (0);

	return channel;
}

/*
 * Destroy a previously allocated channel
 */
VOID channel_destroy(Channel *channel)
{
	// Call the close handler as we're being destroyed.
	if (channel->local.dio)
		channel->local.dio(channel, &channel->local, channel->local.dioContext,
				CHANNEL_DIO_MODE_CLOSE, NULL, 0, NULL);

	// Remove the channel from the list of channels
	channel_remove_list_entry(channel);

	// Destroy the buffers
	if (channel->local.buffer)
		free(channel->local.buffer);

	// Destroy the channel context
	free(channel);
}

/*
 * Get the channel's identifier
 */
DWORD channel_get_id(Channel *channel)
{
	return channel->identifier;
}

/*
 * Set the type of channel, such as process, fs, etc.
 */
VOID channel_set_type(Channel *channel, PCHAR type)
{
	if (channel->type)
		free(channel->type);

	channel->type = NULL;

	if (type)
		channel->type = strdup(type);
}

/*
 * Get the channel's type.
 */
PCHAR channel_get_type(Channel *channel)
{
	return channel->type;
}

/*
 * Set the channel's interactive flag
 */
VOID channel_set_interactive(Channel *channel, BOOL interactive)
{
	channel->interactive = interactive;
}

/*
 * Return the channel's interactive flag
 */
BOOL channel_is_interactive(Channel *channel)
{
	return channel->interactive;
}

/*
 * Set the local buffer direct IO handler
 */
VOID channel_set_local_io_handler(Channel *channel, LPVOID dioContext,
		DirectIoHandler dio)
{
	channel_set_buffer_io_handler(&channel->local, dioContext, dio);
}


/*
 * Write the supplied buffer to the remote endpoint of the channel.
 *
 * This will cause the passed buffer to be written in channel->local on the
 * remote endpoint.
 */
DWORD channel_write_to_remote(Remote *remote, Channel *channel, PUCHAR chunk, 
		ULONG chunkLength, PULONG bytesWritten)
{
	Packet *request = packet_create(PACKET_TLV_TYPE_REQUEST, 
			"core_channel_write");
	DWORD res = ERROR_SUCCESS;
	Tlv entries[2];
	DWORD idNbo;

	do
	{
		// Did the allocation fail?
		if (!request)
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		idNbo = htonl(channel_get_id(channel));

		entries[0].header.type   = TLV_TYPE_CHANNEL_ID;
		entries[0].header.length = sizeof(DWORD);
		entries[0].buffer        = (PUCHAR)&idNbo;
		entries[1].header.type   = TLV_TYPE_CHANNEL_DATA;
		entries[1].header.length = chunkLength;
		entries[1].buffer        = chunk;

		// Add the TLV data
		if ((res = packet_add_tlv_group(request, TLV_TYPE_CHANNEL_DATA_GROUP, 
				entries, 2)) != ERROR_SUCCESS)
			break;

		// Transmit the packet
		res = packet_transmit(remote, request, NULL);

	} while (0);

	return res;
}

/*
 * Write data into the local buffer using the established DIO operation for
 * writing.
 */
DWORD channel_write_to_local(Channel *channel, PUCHAR chunk, ULONG chunkLength,
		PULONG bytesWritten)
{
	return channel->local.dio(channel, &channel->local, 
			channel->local.dioContext, CHANNEL_DIO_MODE_WRITE, chunk, 
			chunkLength, bytesWritten);
}

/*
 * Read data from the local buffer using the established DIO operation for 
 * reading.
 */
DWORD channel_read_from_local(Channel *channel, PUCHAR chunk, ULONG chunkLength, 
		PULONG bytesRead)
{
	return channel->local.dio(channel, &channel->local, 
			channel->local.dioContext, CHANNEL_DIO_MODE_READ, chunk, chunkLength,
			bytesRead);
}

/*
 * Sets a given buffer's direct IO handler
 */
VOID channel_set_buffer_io_handler(ChannelBuffer *buffer, LPVOID context,
		DirectIoHandler dio)
{
	// If no direct I/O handler is supplied, use the default
	if (!dio)
	{
		dio     = channel_default_io_handler;
		context = NULL;
	}

	buffer->dioContext = context;
	buffer->dio        = dio;
}

/**********************
 * Remote channel API *
 **********************/

/*
 * Duplicates a completion routine so it can be saved for calling back
 */
ChannelCompletionRoutine *channel_duplicate_completion_routine(
		ChannelCompletionRoutine *in)
{
	ChannelCompletionRoutine *ret = NULL;

	if ((ret = (ChannelCompletionRoutine *)malloc(
			sizeof(ChannelCompletionRoutine))))
		memcpy(ret, in, sizeof(ChannelCompletionRoutine));

	return ret;
}

/*
 * Channel completion routine dispatcher
 */
DWORD _channel_packet_completion_routine(Remote *remote, Packet *packet, 
		LPVOID context, LPCSTR method, DWORD result)
{
	ChannelCompletionRoutine *comp = (ChannelCompletionRoutine *)context;
	DWORD channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);
	Channel *channel = channel_find_by_id(channelId);
	DWORD res = ERROR_NOT_FOUND;

	// If the channel was not found and it isn't an open request, return failure
	if (!channel && strcmp(method, "core_channel_open"))
		return ERROR_NOT_FOUND;

	if ((!strcmp(method, "core_channel_open")) &&
	    (comp->routine.open))
		res = comp->routine.open(remote, channel, comp->context, result);
	else if ((!strcmp(method, "core_channel_read")) &&
	         (comp->routine.read))
	{
		ULONG length = 0, realLength = 0;
		PUCHAR buffer = NULL;

		// Get the number of bytes written
		length = packet_get_tlv_value_uint(packet, TLV_TYPE_LENGTH);

		// Allocate storage for it
		if ((length) && (buffer = (PUCHAR)malloc(length)))
		{
			memset(buffer, 0, length);

			channel_read_from_local(channel, buffer, length, &realLength);
		}

		res = comp->routine.read(remote, channel, comp->context, result,
				buffer, realLength);

		if (buffer)
			free(buffer);
	}
	else if ((!strcmp(method, "core_channel_write")) &&
	         (comp->routine.write))
	{
		Tlv lengthTlv;
		ULONG length = 0;

		// Get the number of bytes written to the channel
		if ((packet_get_tlv(packet, TLV_TYPE_LENGTH, &lengthTlv)
				== ERROR_SUCCESS) &&
		    (lengthTlv.header.length >= sizeof(DWORD)))
			length = ntohl(*(LPDWORD)lengthTlv.buffer);

		res = comp->routine.write(remote, channel, comp->context, result,
				length);
	}
	else if ((!strcmp(method, "core_channel_close")) &&
	         (comp->routine.close))
		res = comp->routine.close(remote, channel, comp->context, result);
	else if ((!strcmp(method, "core_channel_interact")) &&
	         (comp->routine.interact))
		res = comp->routine.interact(remote, channel, comp->context, result);

	// Deallocate the completion context
	free(comp);

	return res;
}

/*
 * Tries to open a channel with the remote endpoint, optionally calling the
 * supplied completion routine upon response.
 */
DWORD channel_open(Remote *remote, Tlv *addend, DWORD addendLength,
		ChannelCompletionRoutine *completionRoutine)
{
	PacketRequestCompletion requestCompletion, *realRequestCompletion = NULL;
	ChannelCompletionRoutine *dupe = NULL;
	DWORD res = ERROR_SUCCESS;
	PCHAR method = "core_channel_open";
	Packet *request;
	Tlv methodTlv;

	do
	{
		// Allocate the request
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST,
				NULL)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the supplied TLVs
		packet_add_tlvs(request, addend, addendLength);

		// If no method TLV as added, add the default one.
		if (packet_get_tlv(request, TLV_TYPE_METHOD,
				&methodTlv) != ERROR_SUCCESS)
			packet_add_tlv_string(request, TLV_TYPE_METHOD,
					method);

		// Initialize the packet completion routine
		if (completionRoutine)
		{
			// Duplicate the completion routine
			dupe = channel_duplicate_completion_routine(completionRoutine);

			requestCompletion.context = dupe;
			requestCompletion.routine = _channel_packet_completion_routine;
			realRequestCompletion     = &requestCompletion;
		}

		// Transmit the packet with the supplied completion routine, if any.
		res = packet_transmit(remote, request, realRequestCompletion);

	} while (0);

	return res;
}

/*
 * Read data from the remote end of the channel.
 */
DWORD channel_read(Channel *channel, Remote *remote, Tlv *addend,
		DWORD addendLength, ULONG length, 
		ChannelCompletionRoutine *completionRoutine)
{
	PacketRequestCompletion requestCompletion, *realRequestCompletion = NULL;
	ChannelCompletionRoutine *dupe = NULL;
	Packet *request;
	DWORD res = ERROR_SUCCESS;
	PCHAR method = "core_channel_read";
	Tlv methodTlv;

	do
	{
		// Allocate an empty request
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST, 
				NULL)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the supplied TLVs
		packet_add_tlvs(request, addend, addendLength);

		// If no method TLV as added, add the default one.
		if (packet_get_tlv(request, TLV_TYPE_METHOD,
				&methodTlv) != ERROR_SUCCESS)
			packet_add_tlv_string(request, TLV_TYPE_METHOD,
					method);

		// Add the channel identifier and the length to read
		packet_add_tlv_uint(request, TLV_TYPE_CHANNEL_ID,
				channel_get_id(channel));
		packet_add_tlv_uint(request, TLV_TYPE_LENGTH,
				length);

		// Initialize the packet completion routine
		if (completionRoutine)
		{
			// Duplicate the completion routine
			dupe = channel_duplicate_completion_routine(completionRoutine);

			requestCompletion.context = dupe;
			requestCompletion.routine = _channel_packet_completion_routine;
			realRequestCompletion     = &requestCompletion;
		}

		// Transmit the packet with the supplied completion routine, if any.
		res = packet_transmit(remote, request, realRequestCompletion);

	} while (0);

	return res;
}

/*
 * Write to the remote end of the channel
 */
DWORD channel_write(Channel *channel, Remote *remote, Tlv *addend,
		DWORD addendLength, PUCHAR buffer, ULONG length, 
		ChannelCompletionRoutine *completionRoutine)
{
	PacketRequestCompletion requestCompletion, *realRequestCompletion = NULL;
	ChannelCompletionRoutine *dupe = NULL;
	DWORD res = ERROR_SUCCESS;
	LPCSTR method = "core_channel_write";
	Packet *request;
	Tlv methodTlv;

	do
	{
		// Allocate a request packet
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST, 
				NULL)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the supplied TLVs
		packet_add_tlvs(request, addend, addendLength);

		// If no method TLV as added, add the default one.
		if (packet_get_tlv(request, TLV_TYPE_METHOD,
				&methodTlv) != ERROR_SUCCESS)
			packet_add_tlv_string(request, TLV_TYPE_METHOD,
					method);

		// Add the channel identifier and the length to write
		packet_add_tlv_uint(request, TLV_TYPE_CHANNEL_ID,
				channel_get_id(channel));
		packet_add_tlv_raw(request, TLV_TYPE_CHANNEL_DATA,
				buffer, length);
		packet_add_tlv_uint(request, TLV_TYPE_LENGTH,
				channel_get_id(channel));

		// Initialize the packet completion routine
		if (completionRoutine)
		{
			// Duplicate the completion routine
			dupe = channel_duplicate_completion_routine(completionRoutine);

			requestCompletion.context = dupe;
			requestCompletion.routine = _channel_packet_completion_routine;
			realRequestCompletion     = &requestCompletion;
		}

		// Transmit the packet with the supplied completion routine, if any.
		res = packet_transmit(remote, request, realRequestCompletion);

	} while (0);

	return res;
}

/*
 * Close the channel provided.
 */
DWORD channel_close(Channel *channel, Remote *remote, Tlv *addend,
		DWORD addendLength, ChannelCompletionRoutine *completionRoutine)
{
	PacketRequestCompletion requestCompletion, *realRequestCompletion = NULL;
	ChannelCompletionRoutine *dupe = NULL;
	LPCSTR method = "core_channel_close";
	DWORD res = ERROR_SUCCESS;
	Packet *request;
	Tlv methodTlv;

	do
	{
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST, 
				NULL)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the supplied TLVs
		packet_add_tlvs(request, addend, addendLength);

		// If no method TLV as added, add the default one.
		if (packet_get_tlv(request, TLV_TYPE_METHOD,
				&methodTlv) != ERROR_SUCCESS)
			packet_add_tlv_string(request, TLV_TYPE_METHOD,
					method);

		// Add the channel identifier
		packet_add_tlv_uint(request, TLV_TYPE_CHANNEL_ID,
				channel_get_id(channel));

		// Initialize the packet completion routine
		if (completionRoutine)
		{
			// Duplicate the completion routine
			dupe = channel_duplicate_completion_routine(completionRoutine);

			requestCompletion.context = dupe;
			requestCompletion.routine = _channel_packet_completion_routine;
			realRequestCompletion     = &requestCompletion;
		}

		// Transmit the packet with the supplied completion routine, if any.
		res = packet_transmit(remote, request, realRequestCompletion);

	} while (0);

	return res;
}

/*
 * Interact with a given channel such that data on the remote end is
 * forwarded in real time rather than being polled.
 */
DWORD channel_interact(Channel *channel, Remote *remote, Tlv *addend,
		DWORD addendLength, BOOL enable, 
		ChannelCompletionRoutine *completionRoutine)
{
	PacketRequestCompletion requestCompletion, *realRequestCompletion = NULL;
	ChannelCompletionRoutine *dupe = NULL;
	LPCSTR method = "core_channel_interact";
	DWORD res = ERROR_SUCCESS;
	Packet *request;
	Tlv methodTlv;

	do
	{
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST, 
				NULL)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the supplied TLVs
		packet_add_tlvs(request, addend, addendLength);

		// If no method TLV as added, add the default one.
		if (packet_get_tlv(request, TLV_TYPE_METHOD,
				&methodTlv) != ERROR_SUCCESS)
			packet_add_tlv_string(request, TLV_TYPE_METHOD,
					method);

		// Add the channel identifier
		packet_add_tlv_uint(request, TLV_TYPE_CHANNEL_ID,
				channel_get_id(channel));

		// Add the enable/disable boolean
		packet_add_tlv_bool(request, TLV_TYPE_BOOL, enable);

		// Initialize the packet completion routine
		if (completionRoutine)
		{
			// Duplicate the completion routine
			dupe = channel_duplicate_completion_routine(completionRoutine);

			requestCompletion.context = dupe;
			requestCompletion.routine = _channel_packet_completion_routine;
			realRequestCompletion     = &requestCompletion;
		}

		// Transmit the packet with the supplied completion routine, if any.
		res = packet_transmit(remote, request, realRequestCompletion);

	} while (0);

	return res;
}

/*********************
 * Channel searching *
 *********************/

/*
 * Find a channel context by its identifier
 */
Channel *channel_find_by_id(DWORD id)
{
	Channel *current;

	for (current = channelList;
	     current;
	     current = current->next)
	{
		if (current->identifier == id)
			break;
	}

	return current;
}

/*
 * Insert a channel into the channel list
 */
VOID channel_add_list_entry(Channel *channel)
{
	if (channelList)
		channelList->prev = channel;

	channel->next = channelList;
	channel->prev = NULL;
	channelList   = channel;
}

/*
 * Remove a channel from the channel list
 */
VOID channel_remove_list_entry(Channel *channel)
{
	if (channel->prev)
		channel->prev->next = channel->next;
	else
		channelList = channel->next;

	if (channel->next)
		channel->next->prev = channel->prev;
}

/**************
 * Default IO *
 **************/

/*
 * Channel default IO operations
 *
 * The default implementation queues and dequeues write/read operations,
 * respectively.
 */
DWORD channel_default_io_handler(Channel *channel, ChannelBuffer *buffer,
		LPVOID context, ChannelDioMode mode, PUCHAR chunk, ULONG length, 
		PULONG bytesXfered)
{
	switch (mode)
	{
		case CHANNEL_DIO_MODE_READ:
			channel_read_buffer(channel, buffer, chunk, length, bytesXfered);
			break;
		case CHANNEL_DIO_MODE_WRITE:
			channel_write_buffer(channel, buffer, chunk, length, bytesXfered);
			break;
		default:
			break;
	}

	return ERROR_SUCCESS;
}

/*
 * Writes arbitrary data into a buffer, optionally allocating more memory 
 * as necessary.
 */
VOID channel_write_buffer(Channel *channel, ChannelBuffer *buffer, 
		PUCHAR chunk, ULONG chunkLength, PULONG bytesWritten)
{
	// Is there enough storage space?
	if (buffer->currentSize + chunkLength > buffer->totalSize)
	{
		PUCHAR newBuffer = NULL;
		ULONG newSize = 0;

		// Calculate the new buffer size
		newSize  = buffer->currentSize + chunkLength;
		newSize += CHANNEL_CHUNK_SIZE + (newSize & (CHANNEL_CHUNK_SIZE - 1));

		// Allocate the storage for the new data
		if (buffer->totalSize)
			newBuffer = (PUCHAR)realloc(buffer->buffer, newSize);
		else
			newBuffer = (PUCHAR)malloc(newSize);

		// Allocation failure?
		if (!newBuffer)
		{
			if (buffer->buffer)
				free(buffer->buffer);

			memset(buffer, 0, sizeof(ChannelBuffer));

			return;
		}

		// Populate the buffer with the updated information
		buffer->buffer    = newBuffer;
		buffer->totalSize = newSize;
	}

	// Copy the chunk data into the buffer
	memcpy(buffer->buffer + buffer->currentSize,
			chunk, chunkLength);

	// Update the current size
	buffer->currentSize += chunkLength;

	if (bytesWritten)
		*bytesWritten = chunkLength;
}

/*
 * Reads a given number of bytes from the front of the buffer,
 * thus removing the data from the buffer.
 */
VOID channel_read_buffer(Channel *channel, ChannelBuffer *buffer, PUCHAR chunk,
		ULONG chunkLength, PULONG bytesRead)
{
	ULONG actualSize = chunkLength;

	// Ensure that data is not read past the end of the buffer
	if (actualSize > buffer->currentSize)
		actualSize = buffer->currentSize;

	// Copy the front portion of the buffer into the chunk
	memcpy(chunk, buffer->buffer, actualSize);

	// Move the buffer forward if there is any left
	if (actualSize != buffer->currentSize)
		memcpy(buffer->buffer, buffer->buffer + actualSize,
				buffer->currentSize - actualSize);

	// Decrement the current used size of the buffer
	buffer->currentSize -= actualSize;

	// Pass back the number of bytes actually read
	if (bytesRead)
		*bytesRead = actualSize;
}
