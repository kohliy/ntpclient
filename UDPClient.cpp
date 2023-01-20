/*
 *
 * (C) 2023 Ashish Kohli
 *
 *  akohli_2004@hotmail.com
 *
 * NTP client.
 *
 * Compiled with Microsoft Visual Studio Professional 2019 Version 16.9.25
 *
 * Tested on Windows 10 Enterprise,21H2 on 20/01/2023.
 *
 *
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif


#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wspiapi.h>
#include <windns.h>
#include <Mstcpip.h>
#include <Ip2string.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strsafe.h>
#include <time.h>


#include <string>
#include <list>

using namespace std;


#pragma comment( lib, "Dnsapi" )
#pragma comment( lib, "ntdll" )
#pragma comment( lib, "Ws2_32" )

#define NTP_TIMESTAMP_DELTA 2208988800ull

#define LI(packet)   (uint8_t) ((packet.li_vn_mode & 0xC0) >> 6) // (li   & 11 000 000) >> 6
#define VN(packet)   (uint8_t) ((packet.li_vn_mode & 0x38) >> 3) // (vn   & 00 111 000) >> 3
#define MODE(packet) (uint8_t) ((packet.li_vn_mode & 0x07) >> 0) // (mode & 00 000 111) >> 0

// Structure that defines the 48 byte NTP packet protocol.

typedef struct
{

    uint8_t li_vn_mode;      // Eight bits. li, vn, and mode.
                             // li.   Two bits.   Leap indicator.
                             // vn.   Three bits. Version number of the protocol.
                             // mode. Three bits. Client will pick mode 3 for client.

    uint8_t stratum;         // Eight bits. Stratum level of the local clock.
    uint8_t poll;            // Eight bits. Maximum interval between successive messages.
    uint8_t precision;       // Eight bits. Precision of the local clock.

    uint32_t rootDelay;      // 32 bits. Total round trip delay time.
    uint32_t rootDispersion; // 32 bits. Max error aloud from primary clock source.
    uint32_t refId;          // 32 bits. Reference clock identifier.

    uint32_t refTm_s;        // 32 bits. Reference time-stamp seconds.
    uint32_t refTm_f;        // 32 bits. Reference time-stamp fraction of a second.

    uint32_t origTm_s;       // 32 bits. Originate time-stamp seconds.
    uint32_t origTm_f;       // 32 bits. Originate time-stamp fraction of a second.

    uint32_t rxTm_s;         // 32 bits. Received time-stamp seconds.
    uint32_t rxTm_f;         // 32 bits. Received time-stamp fraction of a second.

    uint32_t txTm_s;         // 32 bits and the most important field the client cares about. Transmit time-stamp seconds.
    uint32_t txTm_f;         // 32 bits. Transmit time-stamp fraction of a second.

} ntp_packet;              // Total: 384 bits or 48 bytes.

/////////////////////////////////////////////////////////////////////////////////////
char* WideCharToMultiByte_helper(const wchar_t* str);
string WideCharToMultiByte_helper(wstring& w);
int dns_resolve(const wchar_t* fqdn, std::list<std::wstring>& ips);
void getNTPtimeUDP();
/////////////////////////////////////////////////////////////////////////////////////

int main(int argc,char*argv[])
{
    getNTPtimeUDP();
    return 0;
}


void getNTPtimeUDP()
{
	int retval = 0;
	WSADATA wsaData = { 0 };
    SOCKET udpSocket = INVALID_SOCKET;
	std::list<std::wstring> ips;
	std::list<std::wstring>::iterator ipIt;
	const wchar_t* wszServer = L"us.pool.ntp.org";
    char* pTemp = NULL;
    string szServer("");
	struct addrinfo* addrptr = NULL;
	DWORD ip = 0;// inet_addr(strAddr);
	string szIP("");
	sockaddr_in clientService;
	bool bConnected = false;
	bool bDone = false;
	ntp_packet packet = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	ntp_packet resp = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	int n = 0;
	__time64_t now = 0;
	LARGE_INTEGER li = { 0 };
	string sTime("");
	char* p = NULL;

	// Load Winsock
    retval = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (0 != retval)
    {
        printf("WSAStartup failed with error %d\n", retval);
        goto getNTPtimeUDP_end;
    }

	udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (INVALID_SOCKET == udpSocket)
	{
		printf("socket failed: %d\n", WSAGetLastError());
        goto getNTPtimeUDP_end;
	}

	retval = dns_resolve(wszServer, ips);

    pTemp = WideCharToMultiByte_helper(wszServer);
    szServer.clear();
    szServer += pTemp;
    delete[] pTemp;

	if (0 != retval)
	{
        printf("dns resolution failed: %s\n", szServer.c_str());
        goto getNTPtimeUDP_end;
	}

	for (ipIt = ips.begin(); ipIt != ips.end(); ipIt++)
	{
		szIP.clear();
		szIP = WideCharToMultiByte_helper(*(ipIt));

		clientService.sin_family = AF_INET;
		clientService.sin_addr.s_addr = inet_addr(szIP.c_str());
		clientService.sin_port = htons(123);

		retval = connect(udpSocket, (SOCKADDR*)&clientService, sizeof(clientService));
		if (SOCKET_ERROR != retval)
		{
            printf("%s resolved to %s\n", szServer.c_str(), szIP.c_str());
			bConnected = true;
			break;
		}
	}

	if (false == bConnected)
	{
        printf("could not connect to %s\n", szServer.c_str());
        goto getNTPtimeUDP_end;
	}

	// Create and zero out the packet. All 48 bytes worth.
	// ntp_packet packet = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	memset(&packet, 0, sizeof(ntp_packet));

	// Set the first byte's bits to 00,011,011 for li = 0, vn = 3, and mode = 3.
	// The rest will be left set to zero.
	*((char*)&packet + 0) = 0x1b; // Represents 27 in base 10 or 00011011 in base 2.

	do
	{
		n = send(udpSocket, (const char*)&packet, sizeof(ntp_packet), 0);
		if (SOCKET_ERROR == n)
		{
			printf("send failed: error %d\n", WSAGetLastError());
			break;
		}
        printf("sent %d bytes \n", n);

		// Wait and receive the packet back from the server. If n == -1, it failed.

		n = recv(udpSocket, (char*)&resp, sizeof(ntp_packet), 0);

		if (SOCKET_ERROR == n)
		{
			printf("recv failed: error %d\n", WSAGetLastError());
			break;
		}

		printf("recieved %d bytes \n", n);
		bDone = true;
		break;

	} while (true);

	if (false == bDone)
	{
        printf("send or recv failed: %s\n", szServer.c_str());
        goto getNTPtimeUDP_end;
	}

	// These two fields contain the time-stamp seconds as the packet left the NTP server.
	 // The number of seconds correspond to the seconds passed since 1900.
	 // ntohl() converts the bit/byte order from the network's to host's "endianness".

	resp.txTm_s = ntohl(resp.txTm_s); // Time-stamp seconds.
	resp.txTm_f = ntohl(resp.txTm_f); // Time-stamp fraction of a second.

	// Extract the 32 bits that represent the time-stamp seconds (since NTP epoch) from when the packet left the server.
	// Subtract 70 years worth of seconds from the seconds since 1900.
	// This leaves the seconds since the UNIX epoch of 1970.
	// (1900)------------------(1970)**************************************(Time Packet Left the Server)

	li.HighPart = 0;
	li.LowPart = resp.txTm_s;

	now = li.QuadPart;
	now -= NTP_TIMESTAMP_DELTA;

	sTime.clear();
	p = _ctime64(&now);
	if (p)
	{
		sTime += p;
		printf("Time: %s\n", sTime.c_str());
	}
	else
	{
		printf("Error converting time");
	}

getNTPtimeUDP_end:

    if (INVALID_SOCKET != udpSocket)
    {
        closesocket(udpSocket);
    }

    WSACleanup();
	return;
}

int dns_resolve(const wchar_t* fqdn, std::list<std::wstring>& ips)
{
    PDNS_RECORD pQueryResults = NULL;
    PDNS_RECORD pRecord = NULL;
    in_addr address;
    DNS_STATUS status = 0;
    wchar_t wBuf[32];
    std::wstring wsz(L"");
    status = DnsQuery_W(fqdn, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pQueryResults, NULL);

    if (0 != status)
    {
        return status;
    }

    ips.clear();
    pRecord = pQueryResults;
    while (pRecord)
    {
        wsz.clear();
        memset(wBuf, 0, 64);
        address.S_un.S_addr = pRecord->Data.A.IpAddress;
        pRecord = pRecord->pNext;
        RtlIpv4AddressToStringW(&address, wBuf);
        wsz += wBuf;
        ips.push_back(wsz);
    }

    DnsRecordListFree(pQueryResults, DnsFreeRecordList);
    return status;
}

char* WideCharToMultiByte_helper(const wchar_t* str)
{
    int iSize = 0;
    char* sz = NULL;

    iSize = WideCharToMultiByte(CP_ACP, 0, str, -1, NULL, 0, NULL, NULL);

    if (0 == iSize)
    {
        return NULL;
    }

    sz = new char[iSize];

    if (NULL == sz)
    {
        return NULL;
    }

    iSize = WideCharToMultiByte(CP_ACP, 0, str, -1, sz, iSize, NULL, NULL);

    if (0 == iSize)
    {
        delete[] sz;
        return NULL;
    }

    return sz;
}

string WideCharToMultiByte_helper(wstring& w)
{
    string s("");
    char* sz = NULL;

    s.clear();

    if (w.empty())
    {
        return s;
    }

    sz = WideCharToMultiByte_helper(w.c_str());

    if (NULL == sz)
    {
        return s;
    }

    s += sz;
    delete[] sz;
    return s;
}