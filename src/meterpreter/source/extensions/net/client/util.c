#include "../net.h"

/*
 * Open a TCP channel with the remote endpoint
 */
DWORD network_open_tcp_channel(Remote *remote, LPCSTR remoteHost, 
		USHORT remotePort, PacketRequestCompletion *complete)
{
	Packet *request = packet_create(PACKET_TLV_TYPE_REQUEST,
			"network_open_tcp_channel");
	DWORD res = ERROR_SUCCESS;

	do
	{
		// Verify that the packet was allocated
		if (!request)
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the host/port combination
		packet_add_tlv_string(request, TLV_TYPE_NETWORK_GENERAL_REMOTE_HOST,
				remoteHost);
		packet_add_tlv_uint(request, TLV_TYPE_NETWORK_GENERAL_REMOTE_PORT,
				remotePort);

		// Transmit the request
		res = packet_transmit(remote, request, complete);

	} while (0);

	return res;
}
