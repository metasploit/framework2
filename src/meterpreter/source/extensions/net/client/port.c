#include "../net.h"

/********************
 * Command: portfwd *
 ********************/

typedef struct _PortForwardListenerContext
{
	SOCKET                             listenFd;
	DWORD                              lhost;
	LPSTR                              slhost;
	USHORT                             lport;
	LPSTR                              rhost;
	USHORT                             rport;
	HANDLE                             notify;

	struct _PortForwardListenerContext *prev;
	struct _PortForwardListenerContext *next;
} PortForwardListenerContext;

PortForwardListenerContext *listeners = NULL;

/*
 * Completion routine for opening a TCP channel
 */
DWORD portfwd_open_tcp_channel_complete(Remote *remote, Packet *packet, 
		LPVOID context, LPCSTR method, DWORD res)
{
	PortForwardClientContext *pcctx = (PortForwardClientContext *)context;

	if (res == ERROR_SUCCESS)
	{
		DWORD channelId = packet_get_tlv_value_uint(packet,
				TLV_TYPE_CHANNEL_ID);

		// Create a channel from the response
		if (channelId)
			pcctx->channel = channel_create(channelId);

		// Override the default dio handler
		if (pcctx->channel)
		{
			channel_set_type(pcctx->channel, "network_tcp");

			channel_set_local_io_handler(pcctx->channel, pcctx,
					portfwd_client_dio);
		}

		// Create a waitable event for this client connection
		// and insert it into the scheduler's waitable list
		if ((pcctx->notify = WSACreateEvent()))
		{
			WSAEventSelect(pcctx->clientFd, pcctx->notify, FD_READ|FD_CLOSE);

			scheduler_insert_waitable(pcctx->notify, pcctx,
					(WaitableNotifyRoutine)portfwd_local_client_notify);
		}
	}
	else
	{
		console_generic_response_output(remote, packet, "NETWORK",
				"open_tcp_channel");

		portfwd_destroy_client(pcctx);
	}

	return ERROR_SUCCESS;
}

/*
 * Notification handler for when a new connection arrives on a local listener
 */
DWORD portfwd_local_listener_notify(Remote *remote, 
		PortForwardListenerContext *plctx)
{
	PacketRequestCompletion complete;
	PortForwardClientContext *pcctx;
	SOCKET clientFd;

	do
	{
		// Accept the client connection
		if ((clientFd = WSAAccept(plctx->listenFd, NULL, NULL, NULL, 0))
				== INVALID_SOCKET)
			break;

		// Create the client connection
		if (!(pcctx = portfwd_create_client(remote, clientFd)))
			break;

		// Initialize the completion handler
		memset(&complete, 0, sizeof(complete));

		complete.routine = portfwd_open_tcp_channel_complete;
		complete.context = pcctx;

		// Open the TCP channel with the remote endpoint
		if (network_open_tcp_channel(remote, plctx->rhost, plctx->rport,
				&complete) != ERROR_SUCCESS)
			break;

	} while (0);

	// Reset the notification event
	ResetEvent(plctx->notify);

	return ERROR_SUCCESS;
}

/*
 * Create a local listener and associate it with a remote host and port
 */
PortForwardListenerContext *portfwd_create_listener(LPCSTR lhost, USHORT lport,
		LPCSTR rhost, USHORT rport)
{
	PortForwardListenerContext *plctx = NULL;
	struct sockaddr_in s;
	BOOL success = FALSE;
	DWORD on = 1;

	if (!lhost)
		lhost = "0.0.0.0";

	do
	{
		// Allocate storage for the listener context
		if (!(plctx = (PortForwardListenerContext *)malloc(
				sizeof(PortForwardListenerContext))))
			break;

		memset(plctx, 0, sizeof(PortForwardListenerContext));

		// Resolve the local host
		if ((plctx->lhost = inet_addr(lhost)) == (DWORD)-1)
		{
			struct hostent *h;

			if (!(h = gethostbyname(lhost)))
				break;

			memcpy(&plctx->lhost, h->h_addr, h->h_length);
		}

		plctx->slhost = strdup(lhost);
		plctx->lport  = lport;
		plctx->rhost  = strdup(rhost);
		plctx->rport  = rport;

		// Create the listener socket
		if ((plctx->listenFd = WSASocket(AF_INET, SOCK_STREAM, 0,
				NULL, 0, 0)) == SOCKET_ERROR)
			break;

		s.sin_family      = AF_INET;
		s.sin_port        = htons(lport);
		s.sin_addr.s_addr = plctx->lhost;

		// Set the re-use address flag
		if (setsockopt(plctx->listenFd, SOL_SOCKET, SO_REUSEADDR, 
				(PCHAR)&on, sizeof(on)) == SOCKET_ERROR)
			break;

		// Bind to the port
		if (bind(plctx->listenFd, (struct sockaddr *)&s, sizeof(s)) 
				== SOCKET_ERROR)
			break;

		// Set up the backlog
		if (listen(plctx->listenFd, 5) < 0)
			break;

		// Create a notification event
		if (!(plctx->notify = WSACreateEvent()))
			break;

		// Associate the event with the socket
		if (WSAEventSelect(plctx->listenFd, plctx->notify, FD_ACCEPT) 
				== SOCKET_ERROR)
			break;

		// Insert the notification event into the schedulers waitable
		// object list so that asynchronous notifications can be handled
		if (scheduler_insert_waitable(plctx->notify, (LPVOID)plctx,
				(WaitableNotifyRoutine)portfwd_local_listener_notify)
				!= ERROR_SUCCESS)
			break;

		// Insert the listener into the listener list
		plctx->next        = listeners;
		plctx->prev        = NULL;

		if (listeners)
			listeners->prev = plctx;
		listeners          = plctx;

		// Success
		success = TRUE;

	} while (0);

	// Clean up on failure
	if ((!success) &&
	    (plctx))
	{
		if (plctx->listenFd)
			closesocket(plctx->listenFd);

		free(plctx);

		plctx = NULL;
	}

	return plctx;
}

/*
 * Destroy a local listener on a given local host and port
 */
DWORD portfwd_destroy_listener(LPCSTR lhost, USHORT lport)
{
	PortForwardListenerContext *current;
	DWORD res = ERROR_SUCCESS;

	for (current = listeners;
	     current;
	     current = current->next)
	{
		if ((current->slhost) && (lhost) && (strcmp(current->slhost, lhost)))
			continue;

		if (current->lport != lport)
			continue;

		break;
	}

	// If an entry was found, remove it.
	if (current)
	{
		if (current->prev)
			current->prev->next = current->next;
		else
			listeners = current->next;

		if (current->next)
			current->next->prev = current->prev;

		if (current->slhost)
			free(current->slhost);
		if (current->rhost)
			free(current->rhost);

		if (current->listenFd)
			closesocket(current->listenFd);
		if (current->notify)
		{
			scheduler_remove_waitable(current->notify);

			CloseHandle(current->notify);
		}

		free(current);
	}
	else
		res = ERROR_NOT_FOUND;

	return res;
}

/*
 * Forward a local port to a remote host:port on the remote end of the tunnel
 */
DWORD cmd_portfwd(Remote *remote, UINT argc, CHAR **argv)
{
	PortForwardListenerContext *plctx = NULL;
	DWORD res = ERROR_SUCCESS;
	ArgumentContext arg;
	BOOL printBanner = FALSE;
	LPCSTR command = NULL, lhost = NULL, rhost = NULL;
	USHORT lport = 0, rport = 0;
	BOOL proxy = FALSE;

	memset(&arg, 0, sizeof(arg));

	do
	{
		// No arguments?
		if (argc == 1)
		{
			printBanner = TRUE;
			break;
		}

		// Parse the arguments
		while (args_parse(argc, argv, "arvL:l:h:p:P", &arg) == ERROR_SUCCESS)
		{
			switch (arg.toggle)
			{
				case 'a':
					command = "network_portfwd_add";
					break;
				case 'r':
					command = "network_portfwd_remove";
					break;
				case 'v':
					command = "network_portfwd_view";
					break;
				case 'L':
					lhost = arg.argument;
					break;
				case 'l':
					lport = atoi(arg.argument) & 0xffff;
					break;
				case 'h':
					rhost = arg.argument;
					break;
				case 'p':
					rport = atoi(arg.argument) & 0xffff;
					break;
				case 'P':
					proxy = TRUE;
					break;
				default:
					break;
			}
		}

		// Was a valid command found?
		if (!command)
		{
			console_write_output(
					"Error: No command was supplied.\n");

			printBanner = TRUE;
			break;
		}

		// If the command is add, create a local listener
		if (!strcmp(command, "network_portfwd_add"))
		{
			// Was a local host and remote host:port supplied?
			if ((!lport) ||
				 (!rhost) || 
				 (!rport))
			{
				console_write_output(
						"Error: Missing one or more of local port/remote host/remote port.\n");
				break;
			}

			// Create a local listener context
			if (!(plctx = portfwd_create_listener(lhost, lport, rhost, rport)))
			{
				console_write_output(
						"Error: Local listener could not be allocated on %d.\n",
						lport);
				break;
			}
	
			console_write_output(
					"Successfully created local listener on port %d.\n", lport);
		}
		else if (!strcmp(command, "network_portfwd_remove"))
		{
			// Destroy a local listener based on the host/port
			if (portfwd_destroy_listener(lhost, lport) != ERROR_SUCCESS)
			{
				console_write_output(
						"Error: Local listener could not be found for %d.\n",
						lport);
				break;
			}
			
			console_write_output(
					"Successfully removed local listener on port %d.\n", lport);
		}
		else if (!strcmp(command, "network_portfwd_view"))
		{
			PortForwardListenerContext *current;

			console_write_output(
					"Local port forward listeners:\n\n");

			for (current = listeners;
			     current;
			     current = current->next)
				console_write_output(
						"  %s:%d <-> %s:%d\n",
						current->slhost ? current->slhost : "ANY",
						current->lport,
						current->rhost ? current->rhost : "UNK",
						current->rport);
		}

	} while (0);

	if (printBanner)
	{
		console_write_output(
				"Usage: portfwd [ -arv ] [ -L laddr ] [ -l lport ] [ -h rhost ] [ -p rport ]\n"
				"               [ -P ]\n"
				"\n"
				"  -a      Add a port forward\n"
				"  -r      Remove a port forward\n"
				"  -v      View port forward list\n"
				"  -L      The local address to listen on\n"
				"  -l      The local port to listen on\n"
				"  -h      The remote host to connect to\n"
				"  -p      The remote port to connect to\n"
				"  -P      Create a local proxy listener that builds a dynamic port forward.\n");
	}

	return res;
}
