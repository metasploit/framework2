#ifndef _METERPRETER_SOURCE_EXTENSIONS_FS_FS_H
#define _METERPRETER_SOURCE_EXTENSIONS_FS_FS_H

#include "../../common/common.h"

#ifdef METERPRETER_CLIENT_EXTENSION
	#include "../../client/metcli.h"
#endif

#ifdef METERPRETER_SERVER_EXTENSION

// File context use in association with 'file_open'
typedef struct
{
	FILE  *fd;
	DWORD mode;
} FileContext;

#endif

#define TLV_TYPE_EXTENSIONS_FS      14100

/*************
 *   FS      *
 *************/

// File types
#define FILE_TYPE_UNKNOWN   0x0000
#define FILE_TYPE_REGULAR   0x0001
#define FILE_TYPE_DIRECTORY 0x0002

// File modes
#define FILE_MODE_READ      (1 << 0)
#define FILE_MODE_WRITE     (1 << 1)
#define FILE_MODE_READWRITE (FILE_MODE_READ | FILE_MODE_WRITE)

#define TLV_TYPE_FS_PATH                 \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_STRING,        \
				TLV_TYPE_EXTENSIONS_FS,      \
				0)
#define TLV_TYPE_FS_FILE_INFO_GROUP      \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_GROUP,         \
				TLV_TYPE_EXTENSIONS_FS,      \
				1)
#define TLV_TYPE_FS_FILE_MTIME           \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_UINT,          \
				TLV_TYPE_EXTENSIONS_FS,      \
				2)
#define TLV_TYPE_FS_FILE_SIZE            \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_UINT,          \
				TLV_TYPE_EXTENSIONS_FS,      \
				3)
#define TLV_TYPE_FS_FILE_TYPE            \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_UINT,          \
				TLV_TYPE_EXTENSIONS_FS,      \
				4)
#define TLV_TYPE_FS_TARGET_PATH          \
		TLV_TYPE_FS_PATH
#define TLV_TYPE_FS_SOURCE_PATH          \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_STRING,        \
				TLV_TYPE_EXTENSIONS_FS,      \
				5)
#define TLV_TYPE_FS_MODE                 \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_UINT,          \
				TLV_TYPE_EXTENSIONS_FS,      \
				6)

#endif
