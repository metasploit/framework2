#include "../sys.h"

/*******************
 * Command: getuid *
 *******************/

/*
 * Completion routine for the getuid request
 */
DWORD cmd_getuid_complete(Remote *remote, Packet *packet, LPVOID context,
		LPCSTR method, DWORD res)
{
	if (res == ERROR_SUCCESS)
	{
		PCHAR username = packet_get_tlv_value_string(packet, TLV_TYPE_USER_NAME);

		console_write_output("\n");

		if (username)
			console_write_output(
					"Username: %s\n", username);

		console_write_prompt();
	}
	else
		console_generic_response_output(remote, packet, "SYS", "getuid");

	return ERROR_SUCCESS;
}

/*
 * Gets the remote user information that the meterpreter server process
 * is executing as
 */
DWORD cmd_getuid(Remote *remote, UINT argc, CHAR **argv)
{
	PacketRequestCompletion complete;
	DWORD res = ERROR_SUCCESS;
	Packet *request;

	do
	{
		// Allocate a packet
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST,
				"sys_getuid")))
		{
			console_write_output(
					"Error: Packet allocation failure.\n");
			break;
		}

		memset(&complete, 0, sizeof(complete));

		complete.routine = cmd_getuid_complete;

		// Transmit the request
		res = packet_transmit(remote, request, &complete);

	} while (0);
	
	return res;
}

/*******************
 * Command: sysinfo *
 *******************/

/*
 * Completion routine for the sysinfo request
 */
DWORD cmd_sysinfo_complete(Remote *remote, Packet *packet, LPVOID context,
		LPCSTR method, DWORD res)
{
	if (res == ERROR_SUCCESS)
	{
		PCHAR computer, os;
		
		computer = packet_get_tlv_value_string(packet, TLV_TYPE_COMPUTER_NAME);
		os       = packet_get_tlv_value_string(packet, TLV_TYPE_OS_NAME);

		console_write_output("\n");

		if (computer)
			console_write_output(
					"Computer: %s\n", computer);
		if (os)
			console_write_output(
					"OS      : %s\n", os);

		console_write_prompt();
	}
	else
		console_generic_response_output(remote, packet, "SYS", "sysinfo");

	return ERROR_SUCCESS;
}

/*
 * Request system information from the remote machine
 */
DWORD cmd_sysinfo(Remote *remote, UINT argc, CHAR **argv)
{
	PacketRequestCompletion complete;
	DWORD res = ERROR_SUCCESS;
	Packet *request;

	do
	{
		// Allocate a packet
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST,
				"sys_sysinfo")))
		{
			console_write_output(
					"Error: Packet allocation failure.\n");
			break;
		}

		memset(&complete, 0, sizeof(complete));

		complete.routine = cmd_sysinfo_complete;

		// Transmit the request
		res = packet_transmit(remote, request, &complete);

	} while (0);
	
	return res;
}
