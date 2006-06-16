#include "../net.h"
#include "netchannel.h"

PortForwardClientContext *clients     = NULL;

/*
 * Allocate a client context and insert it into the list
 */
PortForwardClientContext *portfwd_create_client(Remote *remote, SOCKET fd)
{
	PortForwardClientContext *pcctx = NULL;

	if ((pcctx = (PortForwardClientContext *)malloc(
			sizeof(PortForwardClientContext))))
	{
		pcctx->remote    = remote;
		pcctx->clientFd  = fd;
		pcctx->channel   = NULL;
		pcctx->notify    = NULL;

		pcctx->next      = clients;
		pcctx->prev      = NULL;

		// Insert the client into the list
		if (clients)
			clients->prev = pcctx;
		clients          = pcctx;
	}

	return pcctx;
}

/*
 * Deallocate a client context
 */
VOID portfwd_destroy_client(PortForwardClientContext *pcctx)
{
	// Remove the client from the list
	if (pcctx->prev)
		pcctx->prev->next = pcctx->next;
	else
		clients = pcctx->next;

	if (pcctx->next)
		pcctx->next->prev = pcctx->prev;

	// Close the socket/channel
	if (pcctx->clientFd)
		closesocket(pcctx->clientFd);
	if (pcctx->notify)
	{
		scheduler_remove_waitable(pcctx->notify);

		CloseHandle(pcctx->notify);
	}
	if (pcctx->channel)
		channel_close(pcctx->channel, pcctx->remote, NULL, 0, NULL);

	// Deallocate the context
	free(pcctx);
}

/*
 * Notification handler for when a client connection has data
 */
DWORD portfwd_local_client_notify(Remote *remote,
		PortForwardClientContext *pcctx)
{
	UCHAR buf[8192];
	LONG bytesRead;

	// Reset the notification event
	ResetEvent(pcctx->notify);

	// Read data from the client connection
	if (((bytesRead = recv(pcctx->clientFd, buf, sizeof(buf), 0)) 
			== SOCKET_ERROR) || 
	    (bytesRead == 0))
		channel_close(pcctx->channel, pcctx->remote, NULL, 0, NULL);
		//portfwd_destroy_client(pcctx);
	else if (pcctx->channel)
		channel_write(pcctx->channel, pcctx->remote, NULL, 0, buf, bytesRead, 0);
	
	return ERROR_SUCCESS;
}

/*
 * Direct I/O handler for clients
 */
DWORD portfwd_client_dio(Channel *channel, ChannelBuffer *buffer,
		LPVOID context, ChannelDioMode mode, PUCHAR chunk, ULONG length,
		PULONG bytesXfered)
{
	PortForwardClientContext *pcctx = (PortForwardClientContext *)context;
	LONG bytes = 0;
	DWORD res = ERROR_SUCCESS;

	switch (mode)
	{
		case CHANNEL_DIO_MODE_WRITE:
			if ((bytes = send(pcctx->clientFd, chunk, length, 0)) == SOCKET_ERROR)
			{
				bytes = 0;
				res = GetLastError();
				break;
			}
			break;
		case CHANNEL_DIO_MODE_CLOSE:
			pcctx->channel = NULL;

			portfwd_destroy_client(pcctx);
			break;
		default:
			break;
	}

	if (bytesXfered)
		*bytesXfered = bytes;

	return res;
}
