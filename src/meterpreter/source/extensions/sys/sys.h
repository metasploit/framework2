#ifndef _METERPRETER_SOURCE_EXTENSIONS_SYS_SYS_H
#define _METERPRETER_SOURCE_EXTENSIONS_SYS_SYS_H

#include "../../common/common.h"

#ifdef METERPRETER_CLIENT_EXTENSION
	#include "../../client/metcli.h"
#endif

#ifdef METERPRETER_SERVER_EXTENSION
#endif

#define TLV_TYPE_EXTENSIONS_SYS 15000

// getuid
#define TLV_TYPE_USER_NAME               \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_STRING,        \
				TLV_TYPE_EXTENSIONS_SYS,     \
				0)

// sysinfo
#define TLV_TYPE_COMPUTER_NAME           \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_STRING,        \
				TLV_TYPE_EXTENSIONS_SYS,     \
				10)
#define TLV_TYPE_OS_NAME                 \
		MAKE_CUSTOM_TLV(                   \
				TLV_META_TYPE_STRING,        \
				TLV_TYPE_EXTENSIONS_SYS,     \
				11)

#endif
