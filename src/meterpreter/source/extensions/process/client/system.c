#include "../process.h"

/***************
 * Command: ps *
 ***************/

DWORD cmd_ps_complete(Remote *remote, Packet *packet, LPVOID context,
		LPCSTR method, DWORD res)
{
	Tlv process;
	DWORD index;

	console_write_output("\nProcess list:\n");
	console_write_output("\n"
	                "   Pid           Name   Path      \n"
						 " -----   ------------   ----------\n");

	// Enumerate the result
	for (index = 0;
	     packet_enum_tlv(packet, index, TLV_TYPE_PROCESS_GROUP, 
			  &process) == ERROR_SUCCESS;
	     index++)
	{
		Tlv pid, name, path;
		DWORD pidHbo;

		// Get the PID, name, and path
		if (packet_get_tlv_group_entry(packet, &process, 
				TLV_TYPE_PROCESS_PID, &pid) != ERROR_SUCCESS)
			continue;
		if (packet_get_tlv_group_entry(packet, &process, 
				TLV_TYPE_PROCESS_NAME, &name) != ERROR_SUCCESS)
			continue;
		if (packet_get_tlv_group_entry(packet, &process, 
				TLV_TYPE_PROCESS_PATH, &path) != ERROR_SUCCESS)
			continue;

		// Validate arguments
		if ((packet_is_tlv_null_terminated(packet, &path) 
				!= ERROR_SUCCESS) ||
		    (packet_is_tlv_null_terminated(packet, &name) 
				!= ERROR_SUCCESS) ||
		    (pid.header.length != sizeof(DWORD)))
			continue;

		pidHbo = ntohl(*(LPDWORD)pid.buffer);

		console_write_output(" %.5d  %13s   %s\n", pidHbo, (PCHAR)name.buffer, 
				(PCHAR)path.buffer);
	}

	console_write_output("\n   %lu processes\n", index);

	console_write_prompt();

	return ERROR_SUCCESS;
}

/*
 * List processes on the remote machine.
 */
DWORD cmd_ps(Remote *remote, UINT argc, CHAR **argv)
{
	PacketRequestCompletion complete;
	Packet *request = packet_create(PACKET_TLV_TYPE_REQUEST,
			"process_enumerate");

	do
	{
		if (!request)
		{
			console_write_output("PROCESS: Packet allocation failure.\n");
			break;
		}

		console_write_output(
				OUTBOUND_PREFIX " PROCESS: Requesting process list...\n");

		// Initialize the process listing completion routine
		memset(&complete, 0, sizeof(complete));

		complete.context = NULL;
		complete.routine = cmd_ps_complete;

		// Transmit the request to list processes
		packet_transmit(remote, request, &complete);

	} while (0);

	return ERROR_SUCCESS;
}

/********************
 * Command: execute *
 ********************/

/*
 * Redirect channel writes for an interactive process to the screen
 */
DWORD process_execute_dio_handler(Channel *channel, ChannelBuffer *buffer,
		LPVOID context, ChannelDioMode mode, PUCHAR chunk, ULONG length,
		PULONG bytesXfered)
{
	DWORD res = ERROR_NOT_FOUND;

	switch (mode)
	{
		case CHANNEL_DIO_MODE_WRITE:
			console_write_output_raw(chunk, length);
			res = ERROR_SUCCESS;
			break;
		default:
			break;
	}

	if (res != ERROR_SUCCESS)
		res = channel_default_io_handler(channel, buffer, context, mode, chunk,
			length, bytesXfered);

	return res;
}

/*
 * Completion routine for the 'execute' command
 */
DWORD cmd_execute_complete(Remote *remote, Packet *packet, LPVOID context,
		LPCSTR method, DWORD res)
{
	DWORD result = res;
	BOOL textPrinted = FALSE;

	if (res == ERROR_SUCCESS)
	{
		DWORD channelId, pid;
			
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);
		pid       = packet_get_tlv_value_uint(packet, TLV_TYPE_PROCESS_PID);

		console_write_output("\n");

		// Create the local instance of the channel if one was allocated
		if (channelId)
		{
			Channel *channel;

			console_write_output(
					INBOUND_PREFIX " PROCESS: Allocated channel %lu for new process.\n",
					channelId, pid);

			if ((channel = channel_create(channelId)))
			{
				channel_set_type(channel, "process");

				// Override the default I/O handler to allow for interactive output
				channel_set_local_io_handler(channel, NULL,
						process_execute_dio_handler);
			}

			textPrinted = TRUE;
		}

		console_write_output(
				INBOUND_PREFIX " PROCESS: execute succeeded, process id is %lu.\n", 
				pid);
	}
	else
		console_write_output(
				"\n"
				INBOUND_PREFIX " PROCESS: execute failed, result %lu.\n", res);

	console_write_prompt();

	return result;
}

/*
 * Executes a process on the remote machine
 *
 * Arguments:
 *
 *   [ -f file ] [ -a arguments ] [-h] [ -c ] 
 *
 *
 *   -f <file>  The file name to execute
 *   -a <args>  The arguments 
 *   -H         Hidden
 *   -c         Channelize the output.  This allows
 *              the output to be read from a channel identifier.
 */
DWORD cmd_execute(Remote *remote, UINT argc, CHAR **argv)
{
	BOOL hidden = FALSE, channelized = FALSE, printBanner = FALSE;
	DWORD res = ERROR_SUCCESS, executeFlags = 0;
	PCHAR executable = NULL, arguments = NULL;
	PacketRequestCompletion complete;
	ArgumentContext arg;
	Packet *request;

	memset(&arg, 0, sizeof(arg));

	do
	{
		if (argc == 1)
			printBanner = TRUE;

		// Parse the supplied arguments
		while (args_parse(argc, argv, "f:a:Hch", &arg) == ERROR_SUCCESS)
		{
			switch (arg.toggle)
			{
				case 'f':
					executable = arg.argument;
					break;
				case 'a':
					arguments = arg.argument;
					break;
				case 'H':
					hidden = TRUE;
					break;
				case 'c':
					channelized = TRUE;
					break;
				case 'h':
					printBanner = TRUE;
					break;
				default:
					break;
			}
		}

		if (printBanner)
			break;

		// Was a valid executable supplied?
		if (!executable)
		{
			console_write_output(
					"Error: An executable file name must be supplied.\n");
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		// Allocate the request packet
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST,
				"process_execute")))
		{
			console_write_output(
					"Error: The request could not be allocated.\n");
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Populate the execution flags
		if (hidden)
			executeFlags |= PROCESS_EXECUTE_FLAG_HIDDEN;
		if (channelized)
			executeFlags |= PROCESS_EXECUTE_FLAG_CHANNELIZED;

		// Add the executable, arguments, and flags to the request
		packet_add_tlv_string(request, TLV_TYPE_PROCESS_PATH,
				executable);
		packet_add_tlv_uint(request, TLV_TYPE_PROCESS_FLAGS,
				executeFlags);

		if (arguments)
			packet_add_tlv_string(request, TLV_TYPE_PROCESS_ARGUMENTS,
					arguments);

		console_write_output(
				OUTBOUND_PREFIX " PROCESS: Executing '%s'...\n", executable);

		// Initialize the execution completion routine
		memset(&complete, 0, sizeof(complete));

		complete.context = NULL;
		complete.routine = cmd_execute_complete;

		// Transmit the request packet
		res = packet_transmit(remote, request, &complete);

	} while (0);

	if (printBanner)
	{
		console_write_output(
				"Usage: execute -f file [ -a args ] [ -Hc ]\n\n"
				"  -f <file>  The file name to execute\n"
				"  -a <args>  The arguments to pass to the executable\n"
				"  -H         Create the process hidden\n"
				"  -c         Channelize the input and output\n");
	}

	return res;
}

/*****************
 * Command: kill *
 *****************/

/*
 * Kill completion routine
 */
DWORD cmd_kill_complete(Remote *remote, Packet *packet, LPVOID context,
		LPCSTR method, DWORD res)
{
	return console_generic_response_output(remote, packet, "PROCESS", "kill");
}

/*
 * Kill one or more remote processes
 */
DWORD cmd_kill(Remote *remote, UINT argc, CHAR **argv)
{
	PacketRequestCompletion complete;
	Packet *request;
	DWORD res = ERROR_SUCCESS;
	DWORD pid, index;

	do
	{
		// Check to see if we got at least one PID
		if (argc == 1)
		{
			console_write_output(
					"Usage: kill pid1 pid2 pid3 ...\n");
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		// Allocate the request packet
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST,
				"process_kill")))
		{
			console_write_output(
					"Error: The request could not be allocated.\n");
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
	
		// Add the TLVs
		for (index = 1;
		     index < argc;
		     index++)
		{
			pid = strtoul(argv[index], NULL, 10);

			packet_add_tlv_uint(request, TLV_TYPE_PROCESS_PID, pid);
		}

		console_write_output(
				OUTBOUND_PREFIX " PROCESS: Terminating %lu processes...\n", index - 1);

		// Initialize the execution completion routine
		memset(&complete, 0, sizeof(complete));

		complete.context = NULL;
		complete.routine = cmd_kill_complete;

		// Transmit the request packet
		res = packet_transmit(remote, request, &complete);

	} while (0);

	return res;
}
