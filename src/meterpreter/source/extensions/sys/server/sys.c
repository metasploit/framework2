/*
 * This server feature extension provides:
 *
 *  - username
 */
#include "../sys.h"

extern DWORD request_getuid(Remote *remote, Packet *packet);
extern DWORD request_sysinfo(Remote *remote, Packet *packet);

Command customCommands[] =
{
	{ "sys_getuid",
	  { request_getuid,                                    { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "sys_sysinfo",
	  { request_sysinfo,                                   { 0 }, 0 },
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
