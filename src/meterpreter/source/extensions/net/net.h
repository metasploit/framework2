#ifndef _METERPRETER_EXTENSIONS_NET_H
#define _METERPRETER_EXTENSIONS_NET_H

#include "../../common/common.h"
#include <iphlpapi.h>

// Common net API
#include "common/netchannel.h"

#ifdef METERPRETER_CLIENT_EXTENSION

	#include "../../client/metcli.h"

// Internal API
DWORD network_open_tcp_channel(Remote *remote, LPCSTR remoteHost, 
		USHORT remotePort, PacketRequestCompletion *complete);

#endif

#define TLV_TYPE_EXTENSIONS_NETWORK  18000

/***********
 * Network *
 ***********/

/************
 *   System *
 ************/

#define TLV_TYPE_NETWORK_GENERAL_IP          \
		MAKE_CUSTOM_TLV(                       \
				TLV_META_TYPE_UINT,              \
				TLV_TYPE_EXTENSIONS_NETWORK,     \
				0)
#define TLV_TYPE_NETWORK_GENERAL_NETMASK     \
		MAKE_CUSTOM_TLV(                       \
				TLV_META_TYPE_UINT,              \
				TLV_TYPE_EXTENSIONS_NETWORK,     \
				1)
#define TLV_TYPE_NETWORK_GENERAL_GATEWAY_IP  \
		MAKE_CUSTOM_TLV(                       \
				TLV_META_TYPE_UINT,              \
				TLV_TYPE_EXTENSIONS_NETWORK,     \
				2)
#define TLV_TYPE_NETWORK_GENERAL_DNS_IP      \
		MAKE_CUSTOM_TLV(                       \
				TLV_META_TYPE_UINT,              \
				TLV_TYPE_EXTENSIONS_NETWORK,     \
				3)
#define TLV_TYPE_NETWORK_GENERAL_MAC_ADDR    \
		MAKE_CUSTOM_TLV(                       \
				TLV_META_TYPE_RAW,               \
				TLV_TYPE_EXTENSIONS_NETWORK,     \
				4)
#define TLV_TYPE_NETWORK_GENERAL_MAC_NAME    \
		MAKE_CUSTOM_TLV(                       \
				TLV_META_TYPE_STRING,            \
				TLV_TYPE_EXTENSIONS_NETWORK,     \
				5)
#define TLV_TYPE_NETWORK_GENERAL_SUBNET      \
		MAKE_CUSTOM_TLV(                       \
				TLV_META_TYPE_UINT,              \
				TLV_TYPE_EXTENSIONS_NETWORK,     \
				6)

#define TLV_TYPE_NETWORK_GENERAL_REMOTE_HOST \
		MAKE_CUSTOM_TLV(                       \
				TLV_META_TYPE_STRING,            \
				TLV_TYPE_EXTENSIONS_NETWORK,     \
				10)
#define TLV_TYPE_NETWORK_GENERAL_REMOTE_PORT \
		MAKE_CUSTOM_TLV(                       \
				TLV_META_TYPE_UINT,              \
				TLV_TYPE_EXTENSIONS_NETWORK,     \
				11)

#define TLV_TYPE_NETWORK_GENERAL_IFACE_GROUP \
		MAKE_CUSTOM_TLV(                       \
				TLV_META_TYPE_GROUP,             \
				TLV_TYPE_EXTENSIONS_NETWORK,     \
				40)
#define TLV_TYPE_NETWORK_GENERAL_ROUTE_GROUP \
		MAKE_CUSTOM_TLV(                       \
				TLV_META_TYPE_GROUP,             \
				TLV_TYPE_EXTENSIONS_NETWORK,     \
				41)

#endif
