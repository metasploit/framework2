#include "../process.h"

/**********************
 * Command: enumerate *
 **********************/

/*
 * Enumerates the process list and transmits information packet to the caller
 *
 * NOTE: This is implemented only for Windows NT+.
 */
DWORD request_process_enumerate(Remote *remote, Packet *packet)
{
	BOOL (WINAPI *enumProcesses)(LPDWORD pids, DWORD numPids, LPDWORD numPidsNeeded);
	BOOL (WINAPI *enumProcessModules)(HANDLE p, HMODULE *mod, DWORD cb, LPDWORD needed);
	DWORD (WINAPI *getModuleBaseName)(HANDLE p, HMODULE mod, LPTSTR base, 
			DWORD baseSize);
	DWORD (WINAPI *getModuleFileNameEx)(HANDLE p, HMODULE mod, LPTSTR path,
			DWORD pathSize);
	Packet *response = packet_create_response(packet);
	DWORD pids[512], numProcesses, index, needed;
	DWORD res = ERROR_SUCCESS;
	HANDLE psapi = NULL;
	Tlv entries[3];

	do
	{
		// Valid response?
		if (!response)
			break;

		// Open the process API
		if (!(psapi = LoadLibrary("psapi")))
			break;

		// Try to resolve the address of EnumProcesses
		if (!((LPVOID)enumProcesses = 
				(LPVOID)GetProcAddress(psapi, "EnumProcesses")))
			break;

		// Try to resolve the address of EnumProcessModules
		if (!((LPVOID)enumProcessModules = 
				(LPVOID)GetProcAddress(psapi, "EnumProcessModules")))
			break;

		// Try to resolve the address of GetModuleBaseNameA
		if (!((LPVOID)getModuleBaseName = 
				(LPVOID)GetProcAddress(psapi, "GetModuleBaseNameA")))
			break;

		// Try to resolve the address of GetModuleFileNameExA
		if (!((LPVOID)getModuleFileNameEx = 
				(LPVOID)GetProcAddress(psapi, "GetModuleFileNameExA")))
			break;

		// Enumerate the process list
		if (!enumProcesses(pids, sizeof(pids), &needed))
			break;

		numProcesses = needed / sizeof(DWORD);

		// Walk the populated process list
		for (index = 0;
		     index < numProcesses;
		     index++)
		{
			CHAR path[1024], name[256];
			DWORD pidNbo;
			HMODULE mod;
			HANDLE p;

			memset(name, 0, sizeof(name));
			memset(path, 0, sizeof(path));

			// Try to attach to the process for querying information
			if (!(p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
					FALSE, pids[index])))
				continue;

			// Enumerate the first module in the process and gets its base name
			if ((!enumProcessModules(p, &mod, sizeof(mod), &needed) ||
			    (getModuleBaseName(p, mod, name, sizeof(name) - 1) == 0)))
			{
				CloseHandle(p);

				continue;
			}

			// Try to get the process' file name
			getModuleFileNameEx(p, mod, path, sizeof(path) - 1);

			pidNbo = htonl(pids[index]);

			// Initialize the TLV entries
			entries[0].header.type   = TLV_TYPE_PROCESS_PID;
			entries[0].header.length = sizeof(DWORD);
			entries[0].buffer        = (PUCHAR)&pidNbo;
			entries[1].header.type   = TLV_TYPE_PROCESS_NAME;
			entries[1].header.length = strlen(name) + 1;
			entries[1].buffer        = name;
			entries[2].header.type   = TLV_TYPE_PROCESS_PATH;
			entries[2].header.length = strlen(path) + 1;
			entries[2].buffer        = path;

			// Add the packet group entry for this item
			packet_add_tlv_group(response, TLV_TYPE_PROCESS_GROUP, 
					entries, 3);

			CloseHandle(p);
		}

		// Success
		res = ERROR_SUCCESS;

	} while (0);

	res = GetLastError();

	// If we were not successful, add an exception to the packet
	if (res != ERROR_SUCCESS)
	{
		if (response)
			packet_add_exception(response, 1,
				"Process enumeration was unsuccessful, %lu.", res);
	}

	if (response)
	{
		DWORD resNbo = htonl(res);

		// Return the result of the call
		packet_add_tlv_raw(response, TLV_TYPE_RESULT, (PUCHAR)&resNbo, 
				sizeof(res));

		// Transmit the response packet
		packet_transmit(remote, response, NULL);
	}

	// Close the psapi library and clean up
	if (psapi)
		FreeLibrary(psapi);

	return res;
}

/********************
 * Command: execute *
 ********************/

typedef struct
{
	HANDLE pStdin;
	HANDLE pStdout;
} ChannelProcessDioContext;

/*
 * Direct I/O handler for process input/output
 */
DWORD process_execute_dio_handler(Channel *channel, ChannelBuffer *buffer,
		LPVOID context, ChannelDioMode mode, PUCHAR chunk, ULONG length,
		PULONG bytesXfered)
{
	ChannelProcessDioContext *ctx = (ChannelProcessDioContext *)context;
	DWORD res = ERROR_SUCCESS;
	DWORD localBytesXfered = 0;

	if (bytesXfered)
		*bytesXfered = 0;

	switch (mode)
	{
		case CHANNEL_DIO_MODE_READ:
			if (!ReadFile(ctx->pStdout, chunk, length, &localBytesXfered, 
					NULL))
				res = GetLastError();
			break;
		case CHANNEL_DIO_MODE_WRITE:
			if (!WriteFile(ctx->pStdin, chunk, length, &localBytesXfered, 
					NULL))
				res = GetLastError();
			break;
		case CHANNEL_DIO_MODE_CLOSE:
			if (channel_is_interactive(channel))
				scheduler_remove_waitable(ctx->pStdout);

			CloseHandle(ctx->pStdin);
			CloseHandle(ctx->pStdout);
			free(ctx);
			break;
		default:
			break;
	}
	
	if (bytesXfered)
		*bytesXfered = localBytesXfered;

	return res;
}

/*
 * Executes a process, optionally opening a channel for reading/writing 
 * output depending on what the caller requested.
 *
 * TLVs:
 *
 * req: TLV_TYPE_PROCESS_PATH      -- The image to execute
 * opt: TLV_TYPE_PROCESS_ARGUMENTS -- Executable arguments
 * opt: TLV_TYPE_PROCESS_FLAGS     -- Execution flags (hidden, etc)
 */
DWORD request_process_execute(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	PCHAR path, arguments, commandLine = NULL;
	DWORD flags = 0, createFlags = 0;
	DWORD res = ERROR_SUCCESS;
	PROCESS_INFORMATION pi;
	HANDLE in[2], out[2];
	BOOL inherit = FALSE;
	STARTUPINFO si;

	// Initialize the startup information
	memset(&si, 0, sizeof(si));

	si.cb = sizeof(si);

	// Initialize pipe handles
	in[0]  = in[1]  = NULL;
	out[0] = out[1] = NULL;

	do
	{
		if (!response)
			break;

		// Get the execution arguments
		path      = packet_get_tlv_value_string(packet, 
				TLV_TYPE_PROCESS_PATH);
		arguments = packet_get_tlv_value_string(packet, 
				TLV_TYPE_PROCESS_ARGUMENTS);
		flags     = packet_get_tlv_value_uint(packet,
				TLV_TYPE_PROCESS_FLAGS);

		// If the remote endpoint provided arguments, combine them with the 
		// executable to produce a command line
		if (path && arguments)
		{
			DWORD commandLineLength = strlen(path) + strlen(arguments) + 2;

			if (!(commandLine = (PCHAR)malloc(commandLineLength)))
			{
				res = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}

			_snprintf(commandLine, commandLineLength, "%s %s", path, arguments);
		}
		else if (path)
			commandLine = path;
		else
		{
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		// If the channelized flag is set, create a pipe for stdin/stdout/stderr
		// such that input can be directed to and from the remote endpoint
		if (flags & PROCESS_EXECUTE_FLAG_CHANNELIZED)
		{
			SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
			Channel *newChannel = channel_create(0);
			ChannelProcessDioContext *ctx;

			// Did the channel allocation succeed?
			if (!newChannel)
			{
				res = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}

			// Set the channel's type to process
			channel_set_type(newChannel, "process");

			// Allocate the direct I/O context
			if (!(ctx = (ChannelProcessDioContext *)malloc(
					sizeof(ChannelProcessDioContext))))
			{
				channel_destroy(newChannel);
				res = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}

			// Allocate the stdin and stdout pipes
			if ((!CreatePipe(&in[0], &in[1], &sa, 0)) ||
			    (!CreatePipe(&out[0], &out[1], &sa, 0)))
			{
				channel_destroy(newChannel);
				free(ctx);
				res = GetLastError();
				break;
			}

			// Initialize the startup info to use the pipe handles
			si.dwFlags   |= STARTF_USESTDHANDLES;
			si.hStdInput  = in[0];
			si.hStdOutput = out[1];
			si.hStdError  = out[1];
			inherit       = TRUE;
			createFlags  |= CREATE_NEW_CONSOLE;

			// Set the context to have the write side of stdin and the read side
			// of stdout
			ctx->pStdin   = in[1];
			ctx->pStdout  = out[0];

			// Set the process' direct I/O handler
			channel_set_local_io_handler(newChannel, ctx, 
					process_execute_dio_handler);

			// Add the channel identifier to the response packet
			packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID,
					channel_get_id(newChannel));
		}

		// If the hidden flag is set, create the process hidden
		if (flags & PROCESS_EXECUTE_FLAG_HIDDEN)
		{
			si.dwFlags     |= STARTF_USESHOWWINDOW;
			si.wShowWindow  = SW_HIDE;
			createFlags    |= CREATE_NO_WINDOW;
		}

		// Try to execute the process
		if (!CreateProcess(NULL, commandLine, NULL, NULL, inherit, 
				createFlags, NULL, NULL, &si, &pi))
		{
			res = GetLastError();
			break;
		}
		else
		{
			packet_add_tlv_uint(response, TLV_TYPE_PROCESS_PID,
					pi.dwProcessId);

			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			res = ERROR_SUCCESS;
		}

	} while (0);

	// Close the read side of stdin and the write side of stdout
	if (in[0])
		CloseHandle(in[0]);
	if (out[1])
		CloseHandle(out[1]);

	// Free the command line if necessary
	if (path && arguments && commandLine)
		free(commandLine);

	// Transmit the response
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

		packet_transmit(remote, response, NULL);
	}

	return res;
}

/*
 * process_kill
 * ------------
 *
 * Terminate one or more processes
 *
 * TLVs
 *
 * req: TLV_TYPE_PROCESS_PID [n]
 */
DWORD request_process_kill(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	Tlv pidTlv;
	DWORD index = 0;

	while ((packet_enum_tlv(packet, index++, TLV_TYPE_PROCESS_PID,
			&pidTlv) == ERROR_SUCCESS) && 
			(pidTlv.header.length >= sizeof(DWORD)))
	{
		DWORD pid = ntohl(*(LPDWORD)pidTlv.buffer);
		HANDLE h = NULL;

		// Try to attach to the process
		if (!(h = OpenProcess(PROCESS_TERMINATE, FALSE, pid)))
		{
			res = GetLastError();
			break;
		}

		if (!TerminateProcess(h, 0))
			res = GetLastError();

		CloseHandle(h);
	}

	// Transmit the response
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

		packet_transmit(remote, response, NULL);
	}

	return res;
}

/**********************************
 * Command: core_channel_interact *
 **********************************/

/*
 * Notification handler that is called back when an interactive
 * process channel has data on its output handle.
 */
DWORD process_interact_data_notify(Remote *remote, LPVOID context)
{
	ChannelProcessDioContext *ctx; 
	Channel *channel = (Channel *)context;
	DWORD bytesRead, bytesAvail = 0;
	CHAR buffer[4096];

	ctx = (ChannelProcessDioContext *)channel->local.dioContext;

	// If data is read successfully from the handler, write it
	// to the remote channel.  Otherwise, close the channel.
	if ((PeekNamedPipe(ctx->pStdout, NULL, 0, NULL, &bytesAvail, NULL)) &&
	    (bytesAvail) &&
	    (ReadFile(ctx->pStdout, buffer, sizeof(buffer) - 1, 
			&bytesRead, NULL)))
		channel_write(channel, remote, NULL, 0, buffer,
				bytesRead, NULL);
	else if (GetLastError() != ERROR_SUCCESS)
		channel_close(channel, remote, NULL, 0, NULL);
	
	return ERROR_SUCCESS;
}

/*
 * Request handler for interacting with a given process channel.
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to operate on
 * req: TLV_TYPE_BOOL       -- Whether or not interactivity is enabled
 */
DWORD request_process_interact(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	ChannelProcessDioContext *ctx; 
	DWORD res = ERROR_SUCCESS, channelId;
	PCHAR channelType;
	Channel *channel;
	BOOL interact;

	do
	{
		// Get the channel identifier & interact flag from the request
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);
		interact  = packet_get_tlv_value_bool(packet, TLV_TYPE_BOOL);

		// Try to find the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Get the channel's type
		channelType = channel_get_type(channel);
		ctx         = channel->local.dioContext;

		// If the channel type is not valid or it's not a process channel,
		// skip it.
		if ((!channelType) ||
          (strcmp(channelType, "process")) ||
		    (!ctx))
		{
			res = ERROR_NOT_FOUND;
			break;
		}
		
		// If interactivity is enabled, register the stdout handle as a waitable
		// object with the scheduler subsystem
		if (interact)
		{
			// Register a waitable event with the scheduler to be have a call back
			// called when the passed in handle satisfies a wait
			res = scheduler_insert_waitable(ctx->pStdout, channel,
					process_interact_data_notify);
		}
		else
		{
			// Remove a previously registered waitable event, if any
			res = scheduler_remove_waitable(ctx->pStdout);
		}

	} while (0);

	// Transmit the response
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);
		packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channelId);

		packet_transmit(remote, response, NULL);
	}

	return res;
}
