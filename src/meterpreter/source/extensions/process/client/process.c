/*
 * This feature module provides an interface to execute and enumerate processes
 * on the remote machine.
 */
#include "../process.h"

extern DWORD cmd_execute(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_kill(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_ps(Remote *remote, UINT argc, CHAR **argv);

ConsoleCommand customCommands[] =
{
	// Process 
	{ "Process",  NULL,         "Process manipulation and execution commands",         1 },
	{ "execute",  cmd_execute,  "Executes a process on the remote machine.",           0 },
	{ "kill",     cmd_kill,     "Terminate a process on the remote machine.",          0 },
	{ "ps",       cmd_ps,       "Lists processes on the remote machine.",              0 },

	// Terminator
	{ NULL,       NULL,         NULL,                                                  0 },
};

/*
 * Register network extensions
 */
DWORD __declspec(dllexport) InitClientExtension()
{
	DWORD index;

	for (index = 0;
	     customCommands[index].name;
	     index++)
		console_register_command(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deregister network extensions
 */
DWORD __declspec(dllexport) DeinitClientExtension()
{
	DWORD index;

	for (index = 0;
	     customCommands[index].name;
	     index++)
		console_deregister_command(&customCommands[index]);

	return ERROR_SUCCESS;
}

