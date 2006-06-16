#include "../fs.h"

extern DWORD request_fs_cwd(Remote *remote, Packet *packet);
extern DWORD request_fs_getcwd(Remote *remote, Packet *packet);
extern DWORD request_fs_ls(Remote *remote, Packet *packet);
extern DWORD request_fs_file_open(Remote *remote, Packet *packet);

Command customCommands[] =
{
	// File system information
	{ "fs_cwd",
	  { request_fs_cwd,                                    { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "fs_getcwd",
	  { request_fs_getcwd,                                 { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "fs_ls",
	  { request_fs_ls,                                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "core_channel_open",
	  { request_fs_file_open,                              { 0 }, 0 },
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
