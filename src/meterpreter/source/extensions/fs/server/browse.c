#include "../fs.h"

/*
 * Changes the current process' working directory to the one specified.
 *
 * req: TLV_TYPE_FS_PATH -- The path to change to
 */
DWORD request_fs_cwd(Remote *remote, Packet *packet)
{
	Tlv pathTlv;
	DWORD res = ERROR_SUCCESS;

	do
	{
		// Get the path TLV sent from the remote side
		if ((res = packet_get_tlv_string(packet, TLV_TYPE_FS_PATH, 
				&pathTlv)) != ERROR_SUCCESS)
			break;

		if (!SetCurrentDirectory((PCHAR)pathTlv.buffer))
		{
			res = GetLastError();
			break;
		}

	} while (0);

	// Transmit the response with whatever error code was determined.
	packet_transmit_empty_response(remote, packet, res);

	return res;
}

/*
 * Get the current process' working directory
 */
DWORD request_fs_getcwd(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	CHAR currentDirectory[1024];
	DWORD res = ERROR_SUCCESS;

	do
	{
		// Allocate a repsonse
		if (!response)
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the current working directory
		if (!GetCurrentDirectory(sizeof(currentDirectory) - 1,
				currentDirectory))
		{
			res = GetLastError();
			break;
		}

		// Add the path to the response
		if ((res = packet_add_tlv_string(response, TLV_TYPE_FS_PATH,
				currentDirectory)) != ERROR_SUCCESS)
			break;

	} while (0);

	if (response)
	{
		// Add the result to the response
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);
	
		// Transmit the response
		packet_transmit(remote, response, NULL);
	}

	return res;
}

DWORD request_fs_ls(Remote *remote, Packet *packet)
{
	Packet *response = NULL;
	WIN32_FIND_DATA data;
	HANDLE first = NULL;
	PCHAR path = "*";
	DWORD res = ERROR_SUCCESS;
	Tlv pathTlv;
	Tlv fileInfo[4];

	do
	{
		// If a directory was specified, use it.
		if (packet_get_tlv_string(packet, TLV_TYPE_FS_PATH,
				&pathTlv) == ERROR_SUCCESS)
			path = (PCHAR)pathTlv.buffer;

		// Create a response packet
		if (!(response = packet_create_response(packet)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the path to the response as an identifier
		packet_add_tlv_string(response, TLV_TYPE_FS_PATH, 
				(PCHAR)path);

		// Try to find the first file
		if ((first = FindFirstFile(path, &data)) == INVALID_HANDLE_VALUE)
		{
			res = GetLastError();
			break;
		}

		do
		{
			DWORD fileType, fileModTime, fileSize;
			PCHAR fileName, slash;

			if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				fileType = FILE_TYPE_DIRECTORY;
			else
				fileType = FILE_TYPE_REGULAR;

			fileName = data.cFileName;

			if ((slash = strrchr(fileName, '\\')))
				fileName = slash + 1;

			fileModTime = htonl(data.ftLastWriteTime.dwLowDateTime);
			fileSize    = htonl(data.nFileSizeLow);
			fileType    = htonl(fileType);

			// Initialize the file information TLVs
			fileInfo[0].header.type   = TLV_TYPE_FS_FILE_MTIME;
			fileInfo[0].header.length = sizeof(DWORD);
			fileInfo[0].buffer        = (PUCHAR)&fileModTime;
			fileInfo[1].header.type   = TLV_TYPE_FS_FILE_SIZE;
			fileInfo[1].header.length = sizeof(DWORD);
			fileInfo[1].buffer        = (PUCHAR)&fileSize;
			fileInfo[2].header.type   = TLV_TYPE_FS_FILE_TYPE;
			fileInfo[2].header.length = sizeof(DWORD);
			fileInfo[2].buffer        = (PUCHAR)&fileType;
			fileInfo[3].header.type   = TLV_TYPE_FS_PATH;
			fileInfo[3].header.length = strlen(fileName) + 1;
			fileInfo[3].buffer        = (PUCHAR)fileName;

			// Add this file's information
			packet_add_tlv_group(response, TLV_TYPE_FS_FILE_INFO_GROUP,
					fileInfo, 4);

		} while (FindNextFile(first, &data));

	} while (0);

	if (first != INVALID_HANDLE_VALUE)
		FindClose(first);

	// If the response packet is valid
	if (response)
	{
		// Set the result
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

		// Transmit the response
		packet_transmit(remote, response, NULL);
	}

	return res;
}
