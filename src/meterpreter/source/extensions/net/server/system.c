#include "../net.h"

/*
 * network_system_ipconfig
 * -----------------------
 *
 * Gets a list of the local interfaces on the machine
 *
 * No TLVs required.
 */
DWORD remote_request_network_system_ipconfig(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	PMIB_IPADDRTABLE table = NULL;
	DWORD tableSize = sizeof(MIB_IPADDRROW) * 33;
	DWORD res = ERROR_SUCCESS, index, entryCount;
	MIB_IFROW iface;
	Tlv entries[5];

	do
	{
		// Allocate memory for reading addresses into
		if (!(table = (PMIB_IPADDRTABLE)malloc(tableSize)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the IP address table
		if (GetIpAddrTable(table, &tableSize, TRUE) != NO_ERROR)
		{
			res = GetLastError();
			break;
		}

		// Enumerate the entries
		for (index = 0;
		     index < table->dwNumEntries;
		     index++)
		{
			entryCount = 0;

			entries[entryCount].header.length = sizeof(DWORD);
			entries[entryCount].header.type   = TLV_TYPE_NETWORK_GENERAL_IP;
			entries[entryCount].buffer        = (PUCHAR)&table->table[index].dwAddr;
			entryCount++;

			entries[entryCount].header.length = sizeof(DWORD);
			entries[entryCount].header.type   = TLV_TYPE_NETWORK_GENERAL_NETMASK;
			entries[entryCount].buffer        = (PUCHAR)&table->table[index].dwMask;
			entryCount++;

			iface.dwIndex = table->table[index].dwIndex;

			// If interface information can get gotten, use it.
			if (GetIfEntry(&iface) == NO_ERROR)
			{
				entries[entryCount].header.length = iface.dwPhysAddrLen;
				entries[entryCount].header.type   = TLV_TYPE_NETWORK_GENERAL_MAC_ADDR;
				entries[entryCount].buffer        = (PUCHAR)iface.bPhysAddr;
				entryCount++;

				if (iface.bDescr)
				{
					entries[entryCount].header.length = iface.dwDescrLen + 1;
					entries[entryCount].header.type   = TLV_TYPE_NETWORK_GENERAL_MAC_NAME;
					entries[entryCount].buffer        = (PUCHAR)iface.bDescr;
					entryCount++;
				}
			}

			// Add the interface group
			packet_add_tlv_group(response, TLV_TYPE_NETWORK_GENERAL_IFACE_GROUP,
					entries, entryCount);
		}

	} while (0);

	if (table)
		free(table);

	// Transmit the response if valid
	if (response)
	{
		packet_add_tlv_uint(packet, TLV_TYPE_RESULT, res);

		packet_transmit(remote, response, NULL);
	}

	return res;
}

/*
 * network_system_route
 * --------------------
 *
 */
DWORD remote_request_network_system_route(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	PMIB_IPFORWARDTABLE table = NULL;
	DWORD tableSize = sizeof(MIB_IPFORWARDROW) * 96;
	DWORD index;

	do
	{
		// Allocate storage for the routing table
		if (!(table = (PMIB_IPFORWARDTABLE)malloc(tableSize)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the routing table
		if (GetIpForwardTable(table, &tableSize, TRUE) != NO_ERROR)
		{
			res = GetLastError();
			break;
		}

		// Enumerate it
		for (index = 0;
		     index < table->dwNumEntries;
		     index++)
		{
			Tlv route[3];

			route[0].header.type   = TLV_TYPE_NETWORK_GENERAL_SUBNET;
			route[0].header.length = sizeof(DWORD);
			route[0].buffer        = (PUCHAR)&table->table[index].dwForwardDest;
			route[1].header.type   = TLV_TYPE_NETWORK_GENERAL_NETMASK;
			route[1].header.length = sizeof(DWORD);
			route[1].buffer        = (PUCHAR)&table->table[index].dwForwardMask;
			route[2].header.type   = TLV_TYPE_NETWORK_GENERAL_GATEWAY_IP;
			route[2].header.length = sizeof(DWORD);
			route[2].buffer        = (PUCHAR)&table->table[index].dwForwardNextHop;

			packet_add_tlv_group(response, TLV_TYPE_NETWORK_GENERAL_ROUTE_GROUP,
					route, 3);
		}

	} while (0);

	if (table)
		free(table);

	// Transmit the response if valid
	if (response)
	{
		packet_add_tlv_uint(packet, TLV_TYPE_RESULT, res);

		packet_transmit(remote, response, NULL);
	}

	return res;
}
