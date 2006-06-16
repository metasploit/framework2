#include "../net.h"

/*
 * network_open_tcp_channel
 * ------------------------
 *
 * Open a channel to a network resource
 */

/*
 * Open a TCP connection and create a channel for it
 */
DWORD open_tcp_channel(Remote *remote, LPCSTR remoteHost,
		USHORT remotePort, Channel **outChannel)
{
	PortForwardClientContext *pcctx = NULL;
	DWORD res = ERROR_SUCCESS;
	Channel *channel = NULL;
	struct sockaddr_in s;
	SOCKET clientFd = 0;

	if (outChannel)
		*outChannel = NULL;

	do
	{
		// Allocate a client socket
		if ((clientFd = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, 0)) 
				== INVALID_SOCKET)
		{
			clientFd = 0;
			res      = GetLastError();
			break;
		}

		s.sin_family      = AF_INET;
		s.sin_port        = htons(remotePort);
		s.sin_addr.s_addr = inet_addr(remoteHost);

		// Resolve the host name locally
		if (s.sin_addr.s_addr == (DWORD)-1)
		{
			struct hostent *h;

			if (!(h = gethostbyname(remoteHost)))
			{
				res = GetLastError();
				break;
			}

			memcpy(&s.sin_addr.s_addr, h->h_addr, h->h_length);
		}

		// Try to connect to the host/port
		if (connect(clientFd, (struct sockaddr *)&s, sizeof(s)) == SOCKET_ERROR)
		{
			res = GetLastError();
			break;
		}

		// Allocate the client context for tracking the connection
		if (!(pcctx = portfwd_create_client(remote, clientFd)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Allocate an uninitialized channel for associated with this connection
		if (!(channel = channel_create(0)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		pcctx->channel = channel;

		// Finally, create a waitable event and insert it into the scheduler's 
		// waitable list
		if ((pcctx->notify = WSACreateEvent()))
		{
			WSAEventSelect(pcctx->clientFd, pcctx->notify, FD_READ|FD_CLOSE);

			scheduler_insert_waitable(pcctx->notify, pcctx,
					portfwd_local_client_notify);
		}

		// Set the channel's direct I/O handler
		channel_set_local_io_handler(channel, pcctx, 
				portfwd_client_dio);

	} while (0);

	// Clean up on failure
	if (res != ERROR_SUCCESS)
	{
		if (pcctx)
			portfwd_destroy_client(pcctx);
		if (clientFd)
			closesocket(clientFd);

		channel = NULL;
	}

	if (outChannel)
		*outChannel = channel;

	return res;
}

/*
 * Handle requests to open a TCP channel to a network resource on this end
 *
 * TLVs
 *
 * req: TLV_TYPE_NETWORK_GENERAL_REMOTE_HOST
 * req: TLV_TYPE_NETWORK_GENERAL_REMOTE_PORT
 */
DWORD remote_request_network_open_tcp_channel(Remote *remote, 
		Packet *packet)
{
	Packet *response = packet_create_response(packet);
	Channel *channel = NULL;
	DWORD res = ERROR_SUCCESS;
	LPCSTR remoteHost = NULL;
	USHORT remotePort = 0;

	do
	{
		// Get the remote host/port
		remoteHost = packet_get_tlv_value_string(packet, 
				TLV_TYPE_NETWORK_GENERAL_REMOTE_HOST);
		remotePort = packet_get_tlv_value_uint(packet,
				TLV_TYPE_NETWORK_GENERAL_REMOTE_PORT) & 0xffff;

		// Invalid host/port?
		if ((!remoteHost) ||
		    (!remotePort))
		{
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		res = open_tcp_channel(remote, remoteHost, remotePort,
				&channel);

		if (channel)
		{
			DWORD channelId = channel_get_id(channel);

			packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID,
					channelId);
		}

	} while (0);

	// Transmit the response
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

		packet_transmit(remote, response, NULL);
	}

	return res;
}
