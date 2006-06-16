#ifndef _METERPRETER_LIB_CHANNEL_H
#define _METERPRETER_LIB_CHANNEL_H

#include "linkage.h"
#include "remote.h"

struct _Channel;
struct _ChannelBuffer;

// Direct I/O operation modes (read/write/close)
typedef enum
{
	CHANNEL_DIO_MODE_OPEN     = 0,
	CHANNEL_DIO_MODE_READ     = 1,
	CHANNEL_DIO_MODE_WRITE    = 2,
	CHANNEL_DIO_MODE_CLOSE    = 3,
	CHANNEL_DIO_MODE_INTERACT = 3,
} ChannelDioMode;

// Direct I/O handler -- used in place of internal buffering for channels
// that can do event based forwarding of buffers.
typedef DWORD (*DirectIoHandler)(struct _Channel *channel, 
		struct _ChannelBuffer *buffer, LPVOID context, ChannelDioMode mode, 
		PUCHAR chunk, ULONG length, PULONG bytesXfered);

// Asynchronous completion routines -- used with channel_open, channel_read, 
// etc.
typedef DWORD (*ChannelOpenCompletionRoutine)(Remote *remote,
		struct _Channel *channel, LPVOID context, DWORD result);
typedef DWORD (*ChannelReadCompletionRoutine)(Remote *remote,
		struct _Channel *channel, LPVOID context, DWORD result, PUCHAR buffer, 
		ULONG bytesRead);
typedef DWORD (*ChannelWriteCompletionRoutine)(Remote *remote,
		struct _Channel *channel, LPVOID context, DWORD result, 
		ULONG bytesWritten);
typedef DWORD (*ChannelCloseCompletionRoutine)(Remote *remote,
		struct _Channel *channel, LPVOID context, DWORD result);
typedef DWORD (*ChannelInteractCompletionRoutine)(Remote *remote,
		struct _Channel *channel, LPVOID context, DWORD result);

// Completion routine wrapper context
typedef struct _ChannelCompletionRoutine
{
	LPVOID context;

	struct
	{
		ChannelOpenCompletionRoutine     open;
		ChannelReadCompletionRoutine     read;
		ChannelWriteCompletionRoutine    write;
		ChannelCloseCompletionRoutine    close;
		ChannelInteractCompletionRoutine interact;
	} routine;

} ChannelCompletionRoutine;

// Logical channel buffer used to queue or for event based updating
typedef struct _ChannelBuffer
{
	PUCHAR          buffer;
	ULONG           currentSize;
	ULONG           totalSize;

	// IO handler -- default is internal queuing
	DirectIoHandler dio;
	LPVOID          dioContext;
} ChannelBuffer;

typedef struct _Channel
{
	// The channel's identifier 
	DWORD           identifier;
	// The type of channel, NULL for default.
	PCHAR           type;
	// Flag for whether or not the channel is currently interactive
	BOOL            interactive;

	// The local output buffer (as in being outputted locally)
	ChannelBuffer   local;

	// Internal attributes for list
	struct _Channel *prev;
	struct _Channel *next;
} Channel;

#define CHANNEL_CHUNK_SIZE 4096

/*
 * Channel manipulation
 */
LINKAGE Channel *channel_create(DWORD identifier);
LINKAGE VOID channel_destroy(Channel *channel);

LINKAGE DWORD channel_get_id(Channel *channel);

LINKAGE VOID channel_set_type(Channel *channel, PCHAR type);
LINKAGE PCHAR channel_get_type(Channel *channel);

LINKAGE VOID channel_set_interactive(Channel *channel, BOOL interactive);
LINKAGE BOOL channel_is_interactive(Channel *channel);

LINKAGE DWORD channel_write_to_remote(Remote *remote, Channel *channel, 
		PUCHAR chunk, ULONG chunkLength, PULONG bytesWritten);

LINKAGE DWORD channel_write_to_local(Channel *channel, PUCHAR chunk,
		ULONG chunkLength, PULONG bytesWritten);
LINKAGE DWORD channel_read_from_local(Channel *channel, PUCHAR chunk,
		ULONG chunkLength, PULONG bytesRead);

LINKAGE VOID channel_set_local_io_handler(Channel *channel, LPVOID dioContext,
		DirectIoHandler dio);

LINKAGE DWORD channel_default_io_handler(Channel *channel, 
		ChannelBuffer *buffer, LPVOID context, ChannelDioMode mode, 
		PUCHAR chunk, ULONG length, PULONG bytesXfered);

/*
 * Remote channel API, used for communication with remotes
 *
 * Each of these routines accepts a completion routine that allows for custom
 * handling of the response.
 */
LINKAGE DWORD channel_open(Remote *remote, Tlv *addend, DWORD addendLength,
		ChannelCompletionRoutine *completionRoutine);
LINKAGE DWORD channel_read(Channel *channel, Remote *remote, Tlv *addend, 
		DWORD addendLength, ULONG length, 
		ChannelCompletionRoutine *completionRoutine);
LINKAGE DWORD channel_write(Channel *channel, Remote *remote, Tlv *addend,
		DWORD addendLength, PUCHAR buffer, ULONG length, 
		ChannelCompletionRoutine *completionRoutine);
LINKAGE DWORD channel_close(Channel *channel, Remote *remote, Tlv *addend,
		DWORD addendLength, ChannelCompletionRoutine *completionRoutine);
LINKAGE DWORD channel_interact(Channel *channel, Remote *remote, Tlv *addend,
		DWORD addendLength, BOOL enable, 
		ChannelCompletionRoutine *completionRoutine);

/*
 * Channel searching
 */
LINKAGE Channel *channel_find_by_id(DWORD id);

#endif
