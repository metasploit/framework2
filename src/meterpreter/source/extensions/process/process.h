#ifndef _METERPRETER_SOURCE_EXTENSIONS_PROCESS_PROCESS_H
#define _METERPRETER_SOURCE_EXTENSIONS_PROCESS_PROCESS_H

#include "../../common/common.h"

#ifdef METERPRETER_CLIENT_EXTENSION
	#include "../../client/metcli.h"
#endif

#ifdef METERPRETER_SERVER_EXTENSION
#endif

#define TLV_TYPE_EXTENSIONS_PROCESS 14080

#define PROCESS_EXECUTE_FLAG_HIDDEN      (1 << 0)
#define PROCESS_EXECUTE_FLAG_CHANNELIZED (1 << 1)

#define LOAD_LIBRARY_FLAG_ON_DISK        (1 << 0)
#define LOAD_LIBRARY_FLAG_EXTENSION      (1 << 1)
#define LOAD_LIBRARY_FLAG_LOCAL          (1 << 2)

#define TLV_TYPE_PROCESS_GROUP           \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_GROUP,         \
				TLV_TYPE_EXTENSIONS_PROCESS, \
				0)
#define TLV_TYPE_PROCESS_PID             \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_UINT,          \
				TLV_TYPE_EXTENSIONS_PROCESS, \
				1)
#define TLV_TYPE_PROCESS_NAME            \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_STRING,        \
				TLV_TYPE_EXTENSIONS_PROCESS, \
				2)
#define TLV_TYPE_PROCESS_PATH            \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_STRING,        \
				TLV_TYPE_EXTENSIONS_PROCESS, \
				3)
#define TLV_TYPE_PROCESS_ARGUMENTS       \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_STRING,        \
				TLV_TYPE_EXTENSIONS_PROCESS, \
				4)
#define TLV_TYPE_PROCESS_FLAGS           \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_UINT,          \
				TLV_TYPE_EXTENSIONS_PROCESS, \
				5)
#define TLV_TYPE_PROCESS_DATA            \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_RAW,           \
				TLV_TYPE_EXTENSIONS_PROCESS, \
				6)
#define TLV_TYPE_PROCESS_TARGET_PATH     \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_STRING,        \
				TLV_TYPE_EXTENSIONS_PROCESS, \
				7)

#endif
