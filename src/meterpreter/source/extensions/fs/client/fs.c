#include "../fs.h"

extern DWORD cmd_cwd(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_getcwd(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_ls(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_upload(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_download(Remote *remote, UINT argc, CHAR **argv);

ConsoleCommand fsCommands[] =
{
	// File system extensions
	{ "File System", NULL,         "File system interaction and manipulation commands",   1 },
	{ "cd",          cmd_cwd,      "Change working directory.",                           0 },
	{ "getcwd",      cmd_getcwd,   "Get the current working directory.",                  0 },
	{ "ls",          cmd_ls,       "List the contents of a directory.",                   0 },
	{ "upload",      cmd_upload,   "Upload one or more files to a remote directory.",     0 },
	{ "download",    cmd_download, "Download one or more files to a local directory.",    0 },

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
	     fsCommands[index].name;
	     index++)
		console_register_command(&fsCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deregister extensions
 */
DWORD __declspec(dllexport) DeinitClientExtension()
{
	DWORD index;

	for (index = 0;
	     fsCommands[index].name;
	     index++)
		console_deregister_command(&fsCommands[index]);

	return ERROR_SUCCESS;
}
