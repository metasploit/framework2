#ifndef _METERPRETER_SOURCE_EXTENSIONS_NET_COMMON_NETCHANNEL_H
#define _METERPRETER_SOURCE_EXTENSIONS_NET_COMMON_NETCHANNEL_H

typedef struct _PortForwardClientContext
{
	Remote                             *remote;
	SOCKET                             clientFd;
	Channel                            *channel;
	HANDLE                             notify;

	struct _PortForwardClientContext   *prev;
	struct _PortForwardClientContext   *next;
} PortForwardClientContext;

PortForwardClientContext *portfwd_create_client(Remote *remote, SOCKET fd);
VOID portfwd_destroy_client(PortForwardClientContext *pcctx);
DWORD portfwd_local_client_notify(Remote *remote,
		PortForwardClientContext *pcctx);
DWORD portfwd_client_dio(Channel *channel, ChannelBuffer *buffer,
		LPVOID context, ChannelDioMode mode, PUCHAR chunk, ULONG length,
		PULONG bytesXfered);

#endif
