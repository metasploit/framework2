/*
 * This client feature extension provides the following:
 *
 *   - get execution username
 */
#include "../sys.h"

extern DWORD cmd_getuid(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_sysinfo(Remote *remote, UINT argc, CHAR **argv);

ConsoleCommand commonCommands[] =
{
	{ "System",      NULL,         "Remote system information",                           1 },
	{ "getuid",      cmd_getuid,   "Get the remote user identifier.",                     0 },
	{ "sysinfo",     cmd_sysinfo,  "Get the system information such as OS version.",      0 },

	// Terminator
	{ NULL,          NULL,         NULL,                                                  0 },
};


/*
 * Register extensions
 */
DWORD __declspec(dllexport) InitClientExtension()
{
	DWORD index;

	for (index = 0;
	     commonCommands[index].name;
	     index++)
		console_register_command(&commonCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deregister extensions
 */
DWORD __declspec(dllexport) DeinitClientExtension()
{
	DWORD index;

	for (index = 0;
	     commonCommands[index].name;
	     index++)
		console_deregister_command(&commonCommands[index]);

	return ERROR_SUCCESS;
}
