#include "../fs.h"

extern DWORD file_open(Remote *remote, LPCSTR file, DWORD mode, 
		ChannelCompletionRoutine *complete);

/*******************
 * Command: upload *
 *******************/

typedef struct
{
	FILE  *fd;
	LPSTR source;
} FileUploadContext;

DWORD file_upload_write_complete(Remote *remote, Channel *channel,
		LPVOID context, DWORD result, ULONG bytesWritten);

/*
 * File upload open completion handler for when a channel for a given file has
 * been opened
 */
DWORD file_upload_open_complete(Remote *remote, Channel *channel, 
		LPVOID context, DWORD result)
{
	FileUploadContext *ctx = (FileUploadContext *)context;
	DWORD res = ERROR_SUCCESS;
	BOOL textPrinted = TRUE;

	do
	{
		// If the result was not successful, no sense in continuing
		if ((!channel) || 
		    (result != ERROR_SUCCESS))
		{
			console_write_output(
					"\n"
					INBOUND_PREFIX " FS: file_upload_open failed, result %lu.\n",
					result);
			res = result;
			break;
		}

		// Try to open the local source file
		if (!(ctx->fd = fopen(ctx->source, "rb")))
		{
			console_write_output(
					"\n"
					"Error: Local file '%s' could not be opened for reading.\n",
					ctx->source);
			res = ERROR_FILE_NOT_FOUND;
			break;
		}

		textPrinted = FALSE;

		res = file_upload_write_complete(remote, channel, context,
				result, 1);

	} while (0);

	// If the result was not successful, clean up the context here
	if (res != ERROR_SUCCESS)
	{
		// Close the channel if it's valid
		if (channel)
			channel_close(channel, remote, NULL, 0, NULL);

		// Deallocate the passed in context
		if (ctx->fd)
			fclose(ctx->fd);

		free(ctx);
	}

	if (textPrinted)
		console_write_prompt();

	return res;
}

/*
 * Channel write complete handler for writing data to the remote endpoint
 * during a file upload.
 */
DWORD file_upload_write_complete(Remote *remote, Channel *channel,
		LPVOID context, DWORD result, ULONG bytesWritten)
{
	FileUploadContext *ctx = (FileUploadContext *)context;
	ChannelCompletionRoutine complete;
	DWORD res = ERROR_SUCCESS;
	BOOL textPrinted = TRUE;
	CHAR buffer[8192];
	LONG bytesRead;

	do
	{
		// If the result was not successful, no sense in continuing
		if ((!channel) || 
		    (result != ERROR_SUCCESS))
		{
			console_write_output(
					"\n"
					INBOUND_PREFIX " FS: file_upload_write failed, result %lu.\n",
					result);
			res = result;
			break;
		}

		// Try to read more data from the local file
		bytesRead = fread(buffer, 1, sizeof(buffer), ctx->fd);

		// If there are no more bytes in the file, send a channel close
		// notification.
		if (bytesRead <= 0)
		{
			console_write_output(
					"\n"
					INBOUND_PREFIX " FS: Upload to '%s' completed.\n", ctx->source);

			channel_close(channel, remote, NULL, 0, NULL);
			break;
		}

		textPrinted = FALSE;

		// Keep writing to the channel until it's done with
		memset(&complete, 0, sizeof(complete));

		complete.context       = (LPVOID)ctx;
		complete.routine.write = file_upload_write_complete;

		// Write the buffer to the wire
		res = channel_write(channel, remote, NULL, 0,
				(PUCHAR)buffer, bytesRead, &complete);

	} while (0);

	// If the result was not successful, clean up the context here
	if (result != ERROR_SUCCESS)
	{
		if (channel)
			channel_close(channel, remote, NULL, 0, NULL);

		// Deallocate the passed in context
		if (ctx->fd)
			fclose(ctx->fd);

		free(ctx);
	}

	if (textPrinted)
		console_write_prompt();

	return res;
}

/*
 * Upload one or more files to the remote machine
 */
DWORD cmd_upload(Remote *remote, UINT argc, CHAR **argv)
{
	DWORD res = ERROR_SUCCESS, index, numUploadFiles;
	ChannelCompletionRoutine completion;

	do
	{
		// Validate arguments
		if (argc < 3)
		{
			console_write_output("Usage: upload [src1] [src2] [...] [dst]\n");
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		// Add all of the source paths
		for (index = 1, numUploadFiles = 0;
		     index < argc - 1;
		     index++, numUploadFiles++)
		{
			FileUploadContext *ctx = (FileUploadContext *)malloc(
					sizeof(FileUploadContext));
			PCHAR remoteFile, slash, remoteFilePath;
			DWORD remoteFilePathSize;

		
			if (!ctx)
				continue;
		
			slash = strrchr(argv[index], '\\');

			// Calculate the source file name
			if (slash)
				remoteFile = slash+1;
			else
				remoteFile = argv[index];
	
			remoteFilePathSize = strlen(remoteFile) + strlen(argv[argc-1]) + 4;
		
			// Allocate storage for the full path to the file being uploaded
			// to.
			if (!(remoteFilePath = (PCHAR)malloc(remoteFilePathSize)))
			{
				free(ctx);
				continue;
			}

			// Build the complete file path
			_snprintf(remoteFilePath, remoteFilePathSize - 1, "%s\\%s",
					argv[argc-1], remoteFile);

			// Copy the source/target and use it as the context
			ctx->source = strdup(argv[index]);
			ctx->fd     = NULL;

			// Call file_upload_open_complete when the the channel
			// for the file has been opened
			memset(&completion, 0, sizeof(completion));

			completion.context      = ctx;
			completion.routine.open = file_upload_open_complete;

			// Open the target file for writing
			res = file_open(remote, remoteFilePath, FILE_MODE_WRITE, &completion);

			console_write_output(
					OUTBOUND_PREFIX " FS: Starting upload from local '%s' to remote '%s'...\n", 
					argv[index], remoteFilePath);

			// Free the remote file path buffer as it's no longer needed.
			free(remoteFilePath);
		}
			
		console_write_output(
				OUTBOUND_PREFIX " FS: Upload of %lu files started.\n",
				numUploadFiles);

	} while (0);

	return res;
}

/*********************
 * Command: download *
 *********************/

typedef struct
{
	FILE  *fd;
	LPSTR target;
} FileDownloadContext;

DWORD file_download_read_complete(Remote *remote, Channel *channel,
		LPVOID context, DWORD result, PUCHAR buffer, ULONG bytesRead);

/*
 * File download open completion handler for when a channel for a given file has
 * been opened and is ready to be read from.
 */
DWORD file_download_open_complete(Remote *remote, Channel *channel, 
		LPVOID context, DWORD result)
{
	ChannelCompletionRoutine complete;
	FileDownloadContext *ctx = (FileDownloadContext *)context;
	DWORD res = ERROR_SUCCESS;
	BOOL textPrinted = TRUE;

	do
	{
		// If the result was not successful, no sense in continuing
		if ((!channel) || 
		    (result != ERROR_SUCCESS))
		{
			console_write_output(
					"\n"
					INBOUND_PREFIX " FS: file_download_open failed, result %lu.\n",
					result);
			res = result;
			break;
		}

		// Try to open the local target file for writing
		if (!(ctx->fd = fopen(ctx->target, "wb")))
		{
			console_write_output(
					"\n"
					"Error: Local file '%s' could not be opened for writing.\n",
					ctx->target);
			res = ERROR_FILE_NOT_FOUND;
			break;
		}

		textPrinted = FALSE;

		// Initialize the completion context for reading
		memset(&complete, 0, sizeof(complete));

		complete.context      = ctx;
		complete.routine.read = file_download_read_complete;

		// Read from the remote file
		res = channel_read(channel, remote, NULL, 0, 8192, &complete);

	} while (0);

	// If the result was not successful, clean up the context here
	if (res != ERROR_SUCCESS)
	{
		// Close the channel if it's valid
		if (channel)
			channel_close(channel, remote, NULL, 0, NULL);

		// Free the context on error
		if (ctx->fd)
			fclose(ctx->fd);

		free(ctx);
	}

	if (textPrinted)
		console_write_prompt();

	return res;
}

/*
 * Download completion routine for a read request.
 */
DWORD file_download_read_complete(Remote *remote, Channel *channel,
		LPVOID context, DWORD result, PUCHAR buffer, ULONG bytesRead)
{
	ChannelCompletionRoutine complete;
	FileDownloadContext *ctx = (FileDownloadContext *)context;
	DWORD bytesWritten;
	BOOL textPrinted = TRUE;
	DWORD res = ERROR_SUCCESS;
	BOOL cleanup = FALSE;

	do
	{
		// If the result was not successful, no sense in continuing
		if ((!channel) || 
		    (result != ERROR_SUCCESS))
		{
			console_write_output(
					"\n"
					INBOUND_PREFIX " FS: file_download_read failed, result %lu.\n",
					result);
			res = result;
			break;
		}

		// Were no bytes read from the remote endpoint?
		if (!bytesRead)
		{
			console_write_output(
					"\n"
					INBOUND_PREFIX " FS: Download to '%s' completed.\n", ctx->target);

			cleanup = TRUE;
			break;
		}

		// Try to read more data from the local file
		if ((bytesWritten = fwrite(buffer, 1, bytesRead, ctx->fd)) <= 0)
		{
			res = GetLastError();

			console_write_output(
					"\n"
					INBOUND_PREFIX " FS: fwrite failed, result %lu.\n", res);
			
			break;
		}

		textPrinted  = FALSE;

		// Initialize the completion context for reading
		memset(&complete, 0, sizeof(complete));

		complete.context      = ctx;
		complete.routine.read = file_download_read_complete;

		// Read from the remote file
		res = channel_read(channel, remote, NULL, 0, 8192, &complete);

	} while (0);

	if (res != ERROR_SUCCESS)
		cleanup = TRUE;

	// If the clean up flag is set, close the channel and close the fd
	if (cleanup)
	{
		if (channel)
			channel_close(channel, remote, NULL, 0, NULL);

		// Free the context on error
		if (ctx->fd)
			fclose(ctx->fd);

		free(ctx);
	}

	// If text was displayed, show the console prompt
	if (textPrinted)
		console_write_prompt();

	return res;
}

/*
 * Download one or more files to the local machine
 *
 * TODO:
 *
 *   - merge cmd_download/cmd_upload for re-use
 */
DWORD cmd_download(Remote *remote, UINT argc, CHAR **argv)
{
	DWORD res = ERROR_SUCCESS, index, numUploadFiles;
	ChannelCompletionRoutine completion;

	do
	{
		// Validate arguments
		if (argc < 3)
		{
			console_write_output("Usage: download [src1] [src2] [...] [dst]\n");
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		// Add all of the source paths
		for (index = 1, numUploadFiles = 0;
		     index < argc - 1;
		     index++, numUploadFiles++)
		{
			FileDownloadContext *ctx = (FileDownloadContext *)malloc(
					sizeof(FileDownloadContext));
			PCHAR localFile, slash, localFilePath;
			DWORD localFilePathSize;

		
			if (!ctx)
				continue;
		
			slash = strrchr(argv[index], '\\');

			// Calculate the source file name
			if (slash)
				localFile = slash+1;
			else
				localFile = argv[index];
	
			localFilePathSize = strlen(localFile) + strlen(argv[argc-1]) + 4;
		
			// Allocate storage for the full path to the file being downloaded
			// to.
			if (!(localFilePath = (PCHAR)malloc(localFilePathSize)))
			{
				free(ctx);
				continue;
			}

			// Build the complete file path
			_snprintf(localFilePath, localFilePathSize - 1, "%s\\%s",
					argv[argc-1], localFile);

			// Use the local file for the target when reading remotely
			ctx->target = localFilePath;
			ctx->fd     = NULL;

			// Call file_download_open_complete when the the channel
			// for the file has been opened
			memset(&completion, 0, sizeof(completion));

			completion.context      = ctx;
			completion.routine.open = file_download_open_complete;

			// Open the target file for writing
			res = file_open(remote, argv[index], FILE_MODE_READ, &completion);

			console_write_output(
					OUTBOUND_PREFIX " FS: Starting download from local '%s' to remote '%s'...\n", 
					argv[index], localFilePath);
		}
			
		console_write_output(
				OUTBOUND_PREFIX " FS: Download of %lu files started.\n",
				numUploadFiles);

	} while (0);

	return res;
}
