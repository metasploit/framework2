#include "../net.h"

extern DWORD cmd_ipconfig(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_route(Remote *remote, UINT argc, CHAR **argv);

extern DWORD cmd_portfwd(Remote *remote, UINT argc, CHAR **ARGV);

ConsoleCommand netCommands[] =
{
	// Network extensions
	{ "Network",  NULL,         "Networking commands",                                 1 },
	{ "ipconfig", cmd_ipconfig, "Display local IP interface information",              0 },
	{ "route",    cmd_route,    "Interact with the local routing table",               0 },

	{ "portfwd",  cmd_portfwd,  "Forward a local port to a remote host:port",          0 },

	{ NULL,       NULL,         NULL,                                                  0 },
};

/*
 * Register network extensions
 */
DWORD __declspec(dllexport) InitClientExtension()
{
	DWORD index;

	for (index = 0;
	     netCommands[index].name;
	     index++)
		console_register_command(&netCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deregister network extensions
 */
DWORD __declspec(dllexport) DeinitClientExtension()
{
	DWORD index;

	for (index = 0;
	     netCommands[index].name;
	     index++)
		console_deregister_command(&netCommands[index]);

	return ERROR_SUCCESS;
}
