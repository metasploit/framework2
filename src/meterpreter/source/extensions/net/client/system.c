#include "../net.h"

/*********************
 * Command: ipconfig *
 *********************/

/*
 * Completion routine for ipconfig request
 */
DWORD cmd_ipconfig_complete(Remote *remote, Packet *packet, LPVOID context,
		LPCSTR method, DWORD res)
{
	if (res == ERROR_SUCCESS)
	{
		Tlv ifaceTlv;
		DWORD index = 0;

		console_write_output(
				"\n"
				INBOUND_PREFIX " NETWORK: Listing IP addresses\n");

		// Process the interface list
		for (index = 0;
		     packet_enum_tlv(packet, index,
				  TLV_TYPE_NETWORK_GENERAL_IFACE_GROUP, &ifaceTlv) 
			  == ERROR_SUCCESS;
		     index++)
		{
			Tlv ipTlv, netmaskTlv, macAddrTlv, macNameTlv;
			CHAR ipString[32], netmaskString[32];
			DWORD ip, netmask;

			// Validate arguments
			if (((packet_get_tlv_group_entry(packet, &ifaceTlv,
					TLV_TYPE_NETWORK_GENERAL_IP, &ipTlv) != ERROR_SUCCESS) ||
			     (ipTlv.header.length < sizeof(DWORD))) ||
			    ((packet_get_tlv_group_entry(packet, &ifaceTlv,
					TLV_TYPE_NETWORK_GENERAL_NETMASK, &netmaskTlv) != ERROR_SUCCESS) ||
			     (netmaskTlv.header.length < sizeof(DWORD))))
				continue;

			if (((packet_get_tlv_group_entry(packet, &ifaceTlv,
					TLV_TYPE_NETWORK_GENERAL_MAC_ADDR, &macAddrTlv) 
						== ERROR_SUCCESS)) &&
			    ((packet_get_tlv_group_entry(packet, &ifaceTlv,
					TLV_TYPE_NETWORK_GENERAL_MAC_NAME, &macNameTlv) 
						== ERROR_SUCCESS)) &&
			    (packet_is_tlv_null_terminated(packet, &macNameTlv) 
				  		== ERROR_SUCCESS))
			{
				UCHAR phys[6];
				PUCHAR realPhys = phys;

				memset(phys, 0, sizeof(phys));

				if (macAddrTlv.header.length >= sizeof(phys))
					realPhys = macAddrTlv.buffer;

				console_write_output(
						"Interface: %s\n"
						"  phys:%02x:%02x:%02x:%02x:%02x:%02x\n", 
						(PCHAR)macNameTlv.buffer,
						realPhys[0], realPhys[1], realPhys[2], realPhys[3], 
						realPhys[4], realPhys[5]);
			}
			else
				console_write_output(
						"Interface: Unknown\n");

			ip      = *(LPDWORD)ipTlv.buffer;
			netmask = *(LPDWORD)netmaskTlv.buffer;

			_snprintf(ipString, sizeof(ipString) - 1, "%hi.%hi.%hi.%hi",
					((PUCHAR)&ip)[0], ((PUCHAR)&ip)[1], ((PUCHAR)&ip)[2], 
					((PUCHAR)&ip)[3]);

			_snprintf(netmaskString, sizeof(netmaskString) - 1, "%hi.%hi.%hi.%hi",
					((PUCHAR)&netmask)[0], ((PUCHAR)&netmask)[1], ((PUCHAR)&netmask)[2],
					((PUCHAR)&netmask)[3]);

			console_write_output(
					"  inet addr:%16s  netmask:%16s\n",
					ipString, netmaskString);
			console_write_output(
					"\n");
		}

		console_write_output("%lu interfaces detected\n", index);
		console_write_prompt();
	}
	else
		console_generic_response_output(remote, packet, "NETWORK", "ipconfig");

	return ERROR_SUCCESS;
}

/*
 * Gets ip configuration information from the remote host
 */
DWORD cmd_ipconfig(Remote *remote, UINT argc, CHAR **argv)
{
	PacketRequestCompletion complete;
	Packet *request;
	DWORD res = ERROR_SUCCESS;

	do
	{
		// Allocate the request
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST,
				"network_system_ipconfig")))
		{
			console_write_output(
					"Error: Packet allocation error.\n");
			break;
		}

		// Initialize the completion routine
		memset(&complete, 0, sizeof(complete));

		complete.routine = cmd_ipconfig_complete;

		console_write_output(
				OUTBOUND_PREFIX " NETWORK: Requesting interface IP information...\n");

		// Transmit the packet
		res = packet_transmit(remote, request, &complete);

	} while (0);

	return res;
}

/******************
 * Command: route *
 ******************/

/*
 * Completion routine for route request
 */
DWORD cmd_route_complete(Remote *remote, Packet *packet, LPVOID context,
		LPCSTR method, DWORD res)
{
	if (res == ERROR_SUCCESS)
	{	
		Tlv routeTlv;
		DWORD index = 0;

		console_write_output(
				"\n"
				INBOUND_PREFIX " NETWORK: Listing routes\n\n");

		console_write_output(
				"          Subnet          Netmask          Gateway\n"
				" ---------------  ---------------  ---------------\n");

		// Process the interface list
		for (index = 0;
		     packet_enum_tlv(packet, index,
				  TLV_TYPE_NETWORK_GENERAL_ROUTE_GROUP, &routeTlv) 
			  == ERROR_SUCCESS;
		     index++)
		{
			char subnetString[32], netmaskString[32], gwString[32]; 
			Tlv subnetTlv, netmaskTlv, gwTlv;

			// Validate arguments
			if (((packet_get_tlv_group_entry(packet, &routeTlv,
					TLV_TYPE_NETWORK_GENERAL_SUBNET, &subnetTlv) != ERROR_SUCCESS) ||
			     (subnetTlv.header.length < sizeof(DWORD))) ||
			    ((packet_get_tlv_group_entry(packet, &routeTlv,
					TLV_TYPE_NETWORK_GENERAL_NETMASK, &netmaskTlv) != ERROR_SUCCESS) ||
			     (netmaskTlv.header.length < sizeof(DWORD))) ||
			    ((packet_get_tlv_group_entry(packet, &routeTlv,
					TLV_TYPE_NETWORK_GENERAL_GATEWAY_IP, &gwTlv) != ERROR_SUCCESS) ||
			     (gwTlv.header.length < sizeof(DWORD))))
				continue;

			sprintf(subnetString, "%hi.%hi.%hi.%hi", 
					subnetTlv.buffer[0],
					subnetTlv.buffer[1],
					subnetTlv.buffer[2],
					subnetTlv.buffer[3]);
			sprintf(netmaskString, "%hi.%hi.%hi.%hi", 
					netmaskTlv.buffer[0],
					netmaskTlv.buffer[1],
					netmaskTlv.buffer[2],
					netmaskTlv.buffer[3]);
			sprintf(gwString, "%hi.%hi.%hi.%hi", 
					gwTlv.buffer[0],
					gwTlv.buffer[1],
					gwTlv.buffer[2],
					gwTlv.buffer[3]);

			console_write_output(
					"%16s %16s %16s\n", subnetString, netmaskString, gwString);
		}
	
		console_write_prompt();
	}
	else
		console_generic_response_output(remote, packet, "NETWORK", "route");


	return ERROR_SUCCESS;
}

/*
 * Gets the routing table from the remote machine
 */
DWORD cmd_route(Remote *remote, UINT argc, CHAR **argv)
{
	PacketRequestCompletion complete;
	Packet *request;
	DWORD res = ERROR_SUCCESS;

	do
	{
		// Allocate the request
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST,
				"network_system_route")))
		{
			console_write_output(
					"Error: Packet allocation error.\n");
			break;
		}

		// Initialize the completion routine
		memset(&complete, 0, sizeof(complete));

		complete.routine = cmd_route_complete;

		console_write_output(
				OUTBOUND_PREFIX " NETWORK: Requesting route table...\n");

		// Transmit the packet
		res = packet_transmit(remote, request, &complete);

	} while (0);

	return res;
}
