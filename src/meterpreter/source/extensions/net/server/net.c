/*
 * This feature module provides commands that can be used to interact
 * with the network on the remote machine.
 */
#include "../net.h"

extern DWORD remote_request_network_system_ipconfig(Remote *remote, 
		Packet *packet);
extern DWORD remote_request_network_system_route(Remote *remote, 
		Packet *packet);
extern DWORD remote_request_network_open_tcp_channel(Remote *remote, 
		Packet *packet);

Command customCommands[] =
{
	// System network information
	{ "network_system_ipconfig",
	  { remote_request_network_system_ipconfig,            { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "network_system_route",
	  { remote_request_network_system_route,               { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Channel opening
	{ "network_open_tcp_channel",
	  { remote_request_network_open_tcp_channel,           { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
};

/*
 * Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	DWORD index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	DWORD index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_deregister(&customCommands[index]);

	return ERROR_SUCCESS;
}
