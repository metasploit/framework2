/*
 * This feature module provides an interface for executing processes,
 * enumerating the process list, and other process execution related things.
 */
#include "../process.h"

extern DWORD request_process_enumerate(Remote *remote, Packet *packet);
extern DWORD request_process_execute(Remote *remote, Packet *packet);
extern DWORD request_process_kill(Remote *remote, Packet *packet);
extern DWORD request_process_interact(Remote *remote, Packet *packet);

Command customCommands[] =
{
	{ "process_enumerate",
	  { request_process_enumerate,         { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
	{ "process_execute",
	  { request_process_execute,           { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
	{ "process_kill",
	  { request_process_kill,              { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                      },
	},

	// File channel interaction
	{ "core_channel_interact",
	  { request_process_interact,          { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                      },
	},

	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	}
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
