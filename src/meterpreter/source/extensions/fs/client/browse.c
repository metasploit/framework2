#include "../fs.h"

/****************
 * Command: cwd *
 ****************/

/*
 * Response handler for a cwd request
 */
DWORD cmd_cwd_complete(Remote *remote, Packet *packet, LPVOID context,
		LPCSTR method, DWORD res)
{
	return console_generic_response_output(remote, packet, "FS", "cwd");
}

/*
 * Changes the working directory on the remote endpoint
 */
DWORD cmd_cwd(Remote *remote, UINT argc, CHAR **argv)
{
	PacketRequestCompletion complete;
	Packet *request;
	DWORD res = ERROR_SUCCESS;

	do
	{
		// Check arguments
		if (argc == 1)
		{
			console_write_output(
					"Usage: cwd directory\n");
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		// Allocate the request packet
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST,
				"fs_cwd")))
		{
			console_write_output("FS: Packet allocation failure.\n");
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the path
		packet_add_tlv_string(request, TLV_TYPE_FS_PATH, argv[1]);

		console_write_output(
				OUTBOUND_PREFIX " FS: Requesting cwd to '%s'...\n", argv[1]);

		// Initialize the packet request completion routine
		memset(&complete, 0, sizeof(complete));

		complete.context = NULL;
		complete.routine = cmd_cwd_complete;

		// Transmit the request
		res = packet_transmit(remote, request, &complete);

	} while (0);

	return res;
}

/*******************
 * Command: getcwd *
 *******************/

/*
 * Response handler for a getcwd request
 */
DWORD cmd_getcwd_complete(Remote *remote, Packet *packet, LPVOID context,
		LPCSTR method, DWORD res)
{
	// If the response is a success response, see if it has a path TLV
	if (res == ERROR_SUCCESS)
	{
		Tlv pathTlv;

		// If the path TLV is a valid string, print it.
		if ((res = packet_get_tlv_string(packet, TLV_TYPE_FS_PATH,
				&pathTlv)) == ERROR_SUCCESS)
			console_write_output(
					"\n"
					INBOUND_PREFIX " FS: getcwd returned '%s'.\n", 
					(PCHAR)pathTlv.buffer);
	}

	// If the result from the packet was unsuccessful or we couldn't find
	// the TLV
	if (res != ERROR_SUCCESS)
		console_write_output(
				"\n"
				INBOUND_PREFIX " FS: getcwd failed, result %lu.\n", 
				res);

	console_write_prompt();

	return res;
}

/*
 * Gets the current working directory on the remote endpoint
 */
DWORD cmd_getcwd(Remote *remote, UINT argc, CHAR **argv)
{
	PacketRequestCompletion complete;
	Packet *request;
	DWORD res = ERROR_SUCCESS;

	do
	{
		// Allocate the request packet
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST,
				"fs_getcwd")))
		{
			console_write_output("FS: Packet allocation failure.\n");
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		console_write_output(
				OUTBOUND_PREFIX " FS: Requesting the cwd...\n");

		// Initialize the packet request completion routine
		memset(&complete, 0, sizeof(complete));

		complete.context = NULL;
		complete.routine = cmd_getcwd_complete;

		// Transmit the request
		res = packet_transmit(remote, request, &complete);

	} while (0);

	return res;
}

/***************
 * Command: ls *
 ***************/

/*
 * Handle the response to a directory listing request
 */
DWORD cmd_ls_complete(Remote *remote, Packet *packet, LPVOID context,
		LPCSTR method, DWORD res)
{
	Tlv fileInfoTlv, pathTlv;
	DWORD index = 0;

	// If the directory listing was successful, process it
	if (res == ERROR_SUCCESS)
	{
		console_write_output("\n");

		// If the server provided us with a directory, state it.
		if (packet_get_tlv_string(packet, TLV_TYPE_FS_PATH, 
				&pathTlv) == ERROR_SUCCESS)
			console_write_output(
					INBOUND_PREFIX " FS: Listing: %s\n\n", 
					(PCHAR)pathTlv.buffer);

		console_write_output(
				"      Size    Type   Name\n"
				" ---------   -----   ----------------\n");

		// Enumerate each of the files in the response
		while (packet_enum_tlv(packet, index++, 
				TLV_TYPE_FS_FILE_INFO_GROUP, &fileInfoTlv) == ERROR_SUCCESS)
		{
			Tlv subPathTlv, typeTlv, sizeTlv;
			DWORD rawType, size;
			float realSize = 0;
			PCHAR type;
			PCHAR sizeType;

			// Make sure enough information was provided.
			if ((packet_get_tlv_group_entry(packet, &fileInfoTlv, 
					TLV_TYPE_FS_FILE_SIZE, &sizeTlv) != ERROR_SUCCESS) ||
			    (packet_get_tlv_group_entry(packet, &fileInfoTlv,
					TLV_TYPE_FS_FILE_TYPE, &typeTlv) != ERROR_SUCCESS) ||
			    (packet_get_tlv_group_entry(packet, &fileInfoTlv,
					TLV_TYPE_FS_PATH, &subPathTlv) != ERROR_SUCCESS))
				continue;

			// If the path TLV is not null terminated, bahumbug.
			if ((packet_is_tlv_null_terminated(packet, &subPathTlv) 
					!= ERROR_SUCCESS) ||
			    (sizeTlv.header.length < sizeof(DWORD)) ||
				 (typeTlv.header.length < sizeof(DWORD)))
				continue;

			rawType = ntohl(*(LPDWORD)typeTlv.buffer);
			size    = ntohl(*(LPDWORD)sizeTlv.buffer);

			// Calculate the short size
			if (size >= (1 << 30))
			{
				realSize = ((FLOAT)size) / ((FLOAT)(1 << 30));
				sizeType = "GB";
			}
			else if (size >= (1 << 20))
			{
				realSize = ((FLOAT)size) / ((FLOAT)(1 << 20));
				sizeType = "MB";
			}
			else if (size >= (1 << 10))
			{
				realSize = ((FLOAT)size) / ((FLOAT)(1 << 10));
				sizeType = "KB";
			}
			else
			{
				realSize = (FLOAT)size;
				sizeType = " B";
			}

			// Extract the file type
			switch (rawType)
			{
				case FILE_TYPE_REGULAR:
					type = "REG";
					break;
				case FILE_TYPE_DIRECTORY:
					type = "DIR";
					break;
				case FILE_TYPE_UNKNOWN:
				default:
					type = "UNK";
					break;
			}

			// Write the output
			console_write_output(
					"%7.2f %s   %5s   %s\n", realSize, sizeType, type,
					(PCHAR)subPathTlv.buffer);
		}

		console_write_prompt();
	}
	else
		console_generic_response_output(remote, packet, "FS", "ls");

	return ERROR_SUCCESS;
}

/*
 * Lists the contents of a directory
 */
DWORD cmd_ls(Remote *remote, UINT argc, CHAR **argv)
{
	PacketRequestCompletion complete;
	Packet *request;
	DWORD res = ERROR_SUCCESS;

	do
	{
		// Allocate the request packet
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST,
				"fs_ls")))
		{
			console_write_output("FS: Packet allocation failure.\n");
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// If a directory is specified, use it.
		if (argc > 1)
			packet_add_tlv_string(request, TLV_TYPE_FS_PATH,
					argv[1]);

		console_write_output(
				OUTBOUND_PREFIX " FS: Requesting a directory listing...\n");

		// Initialize the packet request completion routine
		memset(&complete, 0, sizeof(complete));

		complete.context = NULL;
		complete.routine = cmd_ls_complete;

		// Transmit the request
		res = packet_transmit(remote, request, &complete);

	} while (0);

	return res;
}
