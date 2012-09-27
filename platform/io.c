/***************************************************************************
 *   Copyright (C) 2012 by Tobias Volk                                     *
 *   mail@tobiasvolk.de                                                    *
 *                                                                         *
 *   This program is free software: you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation, either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/


#ifndef F_IO_C
#define F_IO_C


#if defined(__FreeBSD__) || defined(__APPLE__)
#define IO_BSD
#elif defined(WIN32)
#define IO_WINDOWS
#elif defined(__linux__)
#define IO_LINUX
#else
#error Unknown platform
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef IO_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winioctl.h>
#define IO_TAPWIN_IOCTL(request,method) CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define IO_TAPWIN_IOCTL_SET_MEDIA_STATUS IO_TAPWIN_IOCTL(6, METHOD_BUFFERED)
#define IO_TAPWIN_ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define IO_TAPWIN_NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define IO_TAPWIN_USERMODEDEVICEDIR "\\\\.\\Global\\"
#define IO_TAPWIN_TAPSUFFIX ".tap"
#else
#include <poll.h>
#include <netdb.h>
#ifdef IO_LINUX
#include <linux/if_tun.h>
#endif
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#endif


// IDs.
#define IO_FDID_STDIN 0
#define IO_FDID_UDPV4SOCKET 1
#define IO_FDID_UDPV6SOCKET 2
#define IO_FDID_TAP 3
#define IO_FDID_COUNT 4


// The IO state structure.
#ifdef IO_WINDOWS
struct s_io_state_fd {
	int fd;
};
#endif
struct s_io_state {
#ifdef IO_WINDOWS
	OVERLAPPED overlapped_read[IO_FDID_COUNT];
	OVERLAPPED overlapped_write[IO_FDID_COUNT];
	HANDLE event_read[IO_FDID_COUNT];
	unsigned char readbuf[(4096 * IO_FDID_COUNT)];
	struct sockaddr readaddr[IO_FDID_COUNT];
	socklen_t readaddr_len[IO_FDID_COUNT];
	DWORD readbuf_len[IO_FDID_COUNT];
	int readbuf_used[IO_FDID_COUNT];
	struct s_io_state_fd fd[IO_FDID_COUNT];
	HANDLE handle[IO_FDID_COUNT];
#else
#if defined(__APPLE__)
	fd_set fdset;
	int highdesc;
#endif
	struct pollfd fd[IO_FDID_COUNT];
#endif
};


// The IPv4 addr/port structure.
struct s_io_v4addr {
	unsigned char addr[4];
	unsigned char port[2];
};


// The IPv6 addr/port structure.
struct s_io_v6addr {
	unsigned char addr[16];
	unsigned char port[2];
};


// Opens STDIN. Returns 1 if successful.
static int ioOpenSTDIN(struct s_io_state *iostate) {
#ifdef IO_WINDOWS
	return 0; // not implemented
#else
	if(!((fcntl(STDIN_FILENO,F_SETFL,O_NONBLOCK)) < 0)) {
		iostate->fd[IO_FDID_STDIN].fd = STDIN_FILENO;
		iostate->fd[IO_FDID_STDIN].events = POLLIN;
		return 1;
	}
	else {
		return 0;
	}
#endif
}


// Reads from STDIN. Returns number of bytes read.
static int ioReadSTDIN(struct s_io_state *iostate, unsigned char *buf, const int len) {
#ifdef IO_WINDOWS
	return 0; // not implemented
#else
	return read(iostate->fd[IO_FDID_STDIN].fd, buf, len);
#endif
}


// Helper functions for TAP devices on Windows.
#ifdef IO_WINDOWS
#define IO_TAPSEARCH_IF_GUID_FROM_NAME 0
#define IO_TAPSEARCH_IF_NAME_FROM_GUID 1
static char *ioOpenTapSearch(char *value, char *key, int type) {
	int i = 0;
	LONG status;
	DWORD len;
	HKEY net_conn_key;
	BOOL found = FALSE;
	char guid[256];
	char ifname[256];
	char conn_string[512];
	HKEY conn_key;
	DWORD value_type;
	if (!value || !key) {
		return NULL;
	}
	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, IO_TAPWIN_NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &net_conn_key);
	if (status != ERROR_SUCCESS) {
		return NULL;
	}
	while (!found) {
		len = sizeof(guid);
		status = RegEnumKeyEx(net_conn_key, i++, guid, &len, NULL, NULL, NULL, NULL);
		if(status == ERROR_NO_MORE_ITEMS) {
			break;
		}
		else if(status != ERROR_SUCCESS) {
			continue;
		}
		snprintf(conn_string, sizeof(conn_string), "%s\\%s\\Connection", IO_TAPWIN_NETWORK_CONNECTIONS_KEY, guid);
		status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, conn_string, 0, KEY_READ, &conn_key);
		if(status != ERROR_SUCCESS) {
			continue;
		}
		len = sizeof(ifname);
		status = RegQueryValueEx(conn_key, "Name", NULL, &value_type, (BYTE *)ifname, &len);
		if(status != ERROR_SUCCESS || value_type != REG_SZ) {
			RegCloseKey(conn_key);
			continue;
		}
		switch (type) {
		case IO_TAPSEARCH_IF_GUID_FROM_NAME:
			if(!strcmp(key, ifname)) {
				strcpy(value, guid);
				found = TRUE;
			}
			break;
		case IO_TAPSEARCH_IF_NAME_FROM_GUID:
			if(!strcmp(key, guid)) {
				strcpy(value, ifname);
				found = TRUE;
			}
			break;
		default:
			break;
		}
		RegCloseKey(conn_key);
	}
	RegCloseKey(net_conn_key);
	if(found) {
		return value;
	}
	return NULL;
}
static HANDLE ioOpenTapDev(char *guid, char *dev) {
	HANDLE handle;
	ULONG len, status;
	char device_path[512];	
	snprintf(device_path, sizeof(device_path), "%s%s%s", IO_TAPWIN_USERMODEDEVICEDIR, guid, IO_TAPWIN_TAPSUFFIX);
	handle = CreateFile(device_path, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
	if (handle == INVALID_HANDLE_VALUE) {
		return INVALID_HANDLE_VALUE;
	}
	status = TRUE;
	if(!DeviceIoControl(handle, IO_TAPWIN_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &len, NULL)) {
		return INVALID_HANDLE_VALUE;
	}
	return handle;
}
#endif


// Opens TAP device. Returns 1 and a tapname (max. 256 bytes) if successful.
static int ioOpenTap(struct s_io_state *iostate, char *tapname, const char *reqname) {
#if defined(IO_WINDOWS)
	HANDLE handle = INVALID_HANDLE_VALUE;
	HKEY unit_key;
	char guid[256];
	char comp_id[256];
	char enum_name[256];
	char unit_string[512];
	char tmpname[256];
	int tmpname_len;
	BOOL found = FALSE;
	HKEY adapter_key;
	DWORD value_type;
	LONG status;
	DWORD len;
	
	tmpname_len = strlen(reqname);
	if(tmpname_len >= 256) {
		tmpname_len = 255;
	}
	if(tmpname_len > 0) {
		memcpy(tmpname, reqname, tmpname_len);
	}
	else {
		tmpname_len = 0;
	}
	tmpname[tmpname_len] = '\0';
	
	if(tmpname != NULL) {
		if (tmpname[0] != '\0') {
			if (!ioOpenTapSearch(guid, tmpname, IO_TAPSEARCH_IF_GUID_FROM_NAME)) {
				return 0;
			}
			handle = ioOpenTapDev(guid, tmpname);
			if(handle != INVALID_HANDLE_VALUE) {
				if(tapname != NULL) {
					tapname[0] = '\0';
					tmpname_len = strlen(tmpname);
					if(tmpname_len > 0 && tmpname_len < 256) {
						memcpy(tapname, tmpname, tmpname_len);
						tapname[tmpname_len] = '\0';
					}
				}
				iostate->handle[IO_FDID_TAP] = handle;
				return 1;
			}
			else {
				return 0;
			}
		}
	}
	
	int i = 0;
	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, IO_TAPWIN_ADAPTER_KEY, 0, KEY_READ, &adapter_key);
	if (status != ERROR_SUCCESS) {
		return 0;
	}
	while (!found) {
		len = sizeof(enum_name);
		status = RegEnumKeyEx(adapter_key, i++,
			enum_name, &len,
			NULL, NULL, NULL, NULL);
		if (status == ERROR_NO_MORE_ITEMS) {
			break;
		} else if (status != ERROR_SUCCESS) {
			continue;
		}
		snprintf(unit_string, sizeof(unit_string), "%s\\%s", IO_TAPWIN_ADAPTER_KEY, enum_name);
		status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, unit_string, 0, KEY_READ, &unit_key);
		if (status != ERROR_SUCCESS) {
			continue;
		}
		len = sizeof(comp_id);
		status = RegQueryValueEx(unit_key, "ComponentId", NULL, &value_type, (BYTE *)comp_id, &len);
		if (status != ERROR_SUCCESS || value_type != REG_SZ) {
			RegCloseKey(unit_key);
			continue;
		}
		len = sizeof(guid);
		status = RegQueryValueEx(unit_key, "NetCfgInstanceId", NULL, &value_type, (BYTE *)guid, &len);
		if (status != ERROR_SUCCESS || value_type != REG_SZ) {
			RegCloseKey(unit_key);
			continue;
		}
		ioOpenTapSearch(tmpname, guid, IO_TAPSEARCH_IF_NAME_FROM_GUID);
		handle = ioOpenTapDev(guid, tmpname);
		if (handle != INVALID_HANDLE_VALUE) {
			found = TRUE;
		}
		RegCloseKey(unit_key);
	}
	RegCloseKey(adapter_key);
	if(handle != INVALID_HANDLE_VALUE) {
		if(tapname != NULL) {
			tapname[0] = '\0';
			tmpname_len = strlen(tmpname);
			if(tmpname_len > 0 && tmpname_len < 256) {
				memcpy(tapname, tmpname, tmpname_len);
				tapname[tmpname_len] = '\0';
			}
		}
		iostate->handle[IO_FDID_TAP] = handle;
		return 1;
	}
	else {
		return 0;
	}
#elif defined(IO_BSD)
	char file[264];
	int tapfd;
	int req_len;
	int name_len;
	int i;
	
	memset(file, 0, 264);
	strncpy(file, "/dev/", 5);
	
	tapfd = -1;
	
	if(reqname == NULL) {
		req_len = 0;
	}
	else {
		req_len = strnlen(reqname, 255);
	}

	if(req_len > 0) {
		strncpy(&file[5], reqname, 255);
#ifdef __APPLE__
                tapfd = open(file, O_RDWR);
                fcntl(tapfd, F_SETFL, O_NONBLOCK); // fcntl is needed, open(O_NONBLOCK) won't work
#else
                tapfd = open(file, O_RDWR | O_NONBLOCK);
#endif
	}
	else {
		i = 0;
		while((i < 1024) && (tapfd < 0)) {
			snprintf(&file[5], 8, "tap%d", i);
#ifdef __APPLE__
			tapfd = open(file, O_RDWR);
			fcntl(tapfd, F_SETFL, O_NONBLOCK); // fcntl is needed, open(O_NONBLOCK) won't work
#else
			tapfd = open(file, O_RDWR | O_NONBLOCK);
#endif
			i++;
		}
	}
	
	if(tapfd < 0) {
		return 0;
	}

	iostate->fd[IO_FDID_TAP].fd = tapfd;
	iostate->fd[IO_FDID_TAP].events = POLLIN;
	
	if(tapname != NULL) {
		name_len = strlen(&file[5]);
		tapname[0] = '\0';
		if(name_len > 0 && name_len < 256) {
			memcpy(tapname, &file[5], name_len);
			tapname[name_len] = '\0';
		}
	}
	
	return 1;
#elif defined(IO_LINUX)
	struct ifreq ifr;
	char *file = "/dev/net/tun";
	int tapfd = open(file,(O_RDWR | O_NONBLOCK));
	int name_len;

	if(tapfd < 0) {
		return 0;
	}

	memset(&ifr,0,sizeof(struct ifreq));
	ifr.ifr_flags = (IFF_TAP | IFF_NO_PI);
	if(reqname != NULL) {
		strncpy(ifr.ifr_name, reqname, sizeof(ifr.ifr_name) - 1);
	}
	if(ioctl(tapfd,TUNSETIFF,(void *)&ifr) < 0) {
		return 0;
	}

	iostate->fd[IO_FDID_TAP].fd = tapfd;
	iostate->fd[IO_FDID_TAP].events = POLLIN;
	
	if(tapname != NULL) {
		name_len = strlen(ifr.ifr_name);
		tapname[0] = '\0';
		if(name_len > 0 && name_len < 256) {
			memcpy(tapname, ifr.ifr_name, name_len);
			tapname[name_len] = '\0';
		}
	}
	
	return 1;
#else
	return 0;
#endif
}


// Writes to TAP device. Returns number of bytes written.
static int ioWriteTap(struct s_io_state *iostate, const unsigned char *buf, const int len) {
#ifdef IO_WINDOWS
	DWORD ret;
	ret = 0;
	WriteFile(iostate->handle[IO_FDID_TAP], buf, len, NULL, &iostate->overlapped_write[IO_FDID_TAP]);
	GetOverlappedResult(iostate->handle[IO_FDID_TAP], &iostate->overlapped_write[IO_FDID_TAP], &ret, TRUE);
	if(ret > 0) {
		return ret;
	}
	else {
		return 0;
	}
#else
	return write(iostate->fd[IO_FDID_TAP].fd, buf, len);
#endif
}


// Reads from TAP device. Returns number of bytes read.
static int ioReadTap(struct s_io_state *iostate, unsigned char *buf, const int len) {
#ifdef IO_WINDOWS
	int buflen = iostate->readbuf_len[IO_FDID_TAP];
	if(buflen > 0) {
		iostate->readbuf_len[IO_FDID_TAP] = 0;
		if(buflen > 0 && buflen < len) {
			memcpy(buf, &iostate->readbuf[(4096 * IO_FDID_TAP)], buflen);
			return buflen;
		}
		else {
			return 0;
		}
	}
	else {
		return 0;
	}
#else
	return read(iostate->fd[IO_FDID_TAP].fd, buf, len);
#endif
}


// Opens a socket. Returns 1 if successful.
static int ioOpenSocket(int *handle, const char *bindaddress, const char *bindport, const int domain, const int type, const int protocol, const int sockmark) {
	int ret;
	int fd;
	const char *useport;
	const char *useaddr;
	struct addrinfo *d = NULL;
	struct addrinfo *di;
	struct addrinfo hints;
	const char *zero_c = "0";
	memset(&hints,0,sizeof(struct addrinfo));
#ifdef IO_WINDOWS
	if((fd = WSASocket(domain, type, 0, 0, 0, WSA_FLAG_OVERLAPPED)) < 0) return 0;
#else
	if((fd = socket(domain, type, 0)) < 0) return 0;
	int one = 1;
	if((fcntl(fd,F_SETFL,O_NONBLOCK)) < 0) return 0;
	if(domain == AF_INET6) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(int));
#endif
	if(sockmark > 0) {
#ifdef IO_LINUX
	if(setsockopt(fd, SOL_SOCKET, SO_MARK, &sockmark, sizeof(int)) < 0) return 0;
#else
	return 0; // only supported in linux
#endif
	}
	hints.ai_family = domain;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;
	hints.ai_flags = AI_PASSIVE;
	if(bindaddress == NULL) {
		useaddr = NULL;
	}
	else {
		if(strlen(bindaddress) > 0) {
			useaddr = bindaddress;
		}
		else {
			useaddr = NULL;
		}
	}
	if(bindport == NULL) {
		useport = NULL;
	}
	else {
		if(strlen(bindport) > 0) {
			useport = bindport;
		}
		else {
			useport = zero_c;
		}
	}
	if(getaddrinfo(useaddr, useport, &hints, &d) == 0) {
		ret = -1;
		di = d;
		while(di != NULL) {
			if(bind(fd, di->ai_addr, di->ai_addrlen) == 0) {
				ret = fd;
				break;
			}
			di = di->ai_next;
		}
		freeaddrinfo(d);
		if(ret < 0) {
			close(fd);
			return 0;
		}
		*handle = ret;
		return 1;
	}
	else {
		return 0;
	}
}


// Get IPv6 UDP address from name. Returns 1 if successful.
static int ioGetUDPv6Address(struct s_io_v6addr *addr, const char *hostname, const char *port) {
#ifdef IO_WINDOWS
	return 0; // not implemented
#else
	int ret;
	struct sockaddr_in6 *saddr;
	struct addrinfo *d = NULL;
	struct addrinfo hints;
	if(hostname != NULL && port != NULL) {
		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = 0;
		if(getaddrinfo(hostname, port, &hints, &d) == 0) {
			if(d != NULL) {
				saddr = (struct sockaddr_in6 *)d->ai_addr;
				memcpy(addr->addr, saddr->sin6_addr.s6_addr, 16);
				memcpy(addr->port, &saddr->sin6_port, 2);
				ret = 1;
			}
			else {
				ret = 0;
			}
			freeaddrinfo(d);
		}
		else {
			ret = 0;
		}
		return ret;
	}
	else {
		return 0;
	}
#endif
}


// Opens an IPv6 UDP socket. Returns 1 if successful.
static int ioOpenUDPv6Socket(struct s_io_state *iostate, const char *bindaddress, const char *bindport, const int sockmark) {
#ifdef IO_WINDOWS
	return 0; // not implemented
#else
	int fd;
	if(ioOpenSocket(&fd, bindaddress, bindport, AF_INET6, SOCK_DGRAM, 0, sockmark)) {
		iostate->fd[IO_FDID_UDPV6SOCKET].fd = fd;
		iostate->fd[IO_FDID_UDPV6SOCKET].events = POLLIN;
		return 1;
	}
	else {
		return 0;
	}
#endif
}


// Sends an IPv6 UDP packet. Returns length of sent message.
static int ioSendUDPv6Packet(struct s_io_state *iostate, const unsigned char *buf, const int len, struct s_io_v6addr *destination) {
#ifdef IO_WINDOWS
	return 0; // not implemented
#else
	int ret;
	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof(struct sockaddr_in6));
	addr.sin6_family = AF_INET6;
	memcpy(addr.sin6_addr.s6_addr, destination->addr, 16);
	memcpy(&addr.sin6_port, destination->port, 2);
	ret = sendto(iostate->fd[IO_FDID_UDPV6SOCKET].fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6));
	return ret;
#endif
}


// Receives an IPv6 UDP packet. Returns length of received message.
static int ioRecvUDPv6Packet(struct s_io_state *iostate, unsigned char *buf, const int len, struct s_io_v6addr *source) {
#ifdef IO_WINDOWS
	return 0; // not implemented
#else
	struct sockaddr_in6 addr;
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	int ret = recvfrom(iostate->fd[IO_FDID_UDPV6SOCKET].fd, buf, len, 0, (struct sockaddr *)&addr, &addrlen);
	if(ret > 0) {
		memcpy(source->addr, addr.sin6_addr.s6_addr, 16);
		memcpy(source->port, &addr.sin6_port, 2);
	}
	return ret;
#endif
}


// Convert UDPv6 address to 24 bit address.
static void ioConvertAddressFromUDPv6(unsigned char *address, const struct s_io_v6addr *v6addr) {
	memset(address, 0, 24);
	address[0] = 1;
	address[1] = 6;
	address[2] = 1;
	memcpy(&address[4], &v6addr->addr, 16);
	memcpy(&address[20], v6addr->port, 2);
}


// Get IPv4 UDP address from name. Returns 1 if successful.
static int ioGetUDPv4Address(struct s_io_v4addr *addr, const char *hostname, const char *port) {
	int ret;
	struct sockaddr_in *saddr;
	struct addrinfo *d = NULL;
	struct addrinfo hints;
	if(hostname != NULL && port != NULL) {
		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = 0;
		if(getaddrinfo(hostname, port, &hints, &d) == 0) {
			if(d != NULL) {
				saddr = (struct sockaddr_in *)d->ai_addr;
				memcpy(addr->addr, &saddr->sin_addr.s_addr, 4);
				memcpy(addr->port, &saddr->sin_port, 2);
				ret = 1;
			}
			else {
				ret = 0;
			}
			freeaddrinfo(d);
		}
		else {
			ret = 0;
		}
		return ret;
	}
	else {
		return 0;
	}
}


// Opens an IPv4 UDP socket. Returns 1 if successful.
static int ioOpenUDPv4Socket(struct s_io_state *iostate, const char *bindaddress, const char *bindport, const int sockmark) {
	int fd;
	if(ioOpenSocket(&fd, bindaddress, bindport, AF_INET, SOCK_DGRAM, 0, sockmark)) {
		iostate->fd[IO_FDID_UDPV4SOCKET].fd = fd;
#ifdef IO_WINDOWS
#else
		iostate->fd[IO_FDID_UDPV4SOCKET].events = POLLIN;
#endif
		return 1;
	}
	else {
		return 0;
	}
}


// Sends an IPv4 UDP packet. Returns length of sent message.
static int ioSendUDPv4Packet(struct s_io_state *iostate, const unsigned char *buf, const int len, const struct s_io_v4addr *destination) {
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr.s_addr, destination->addr, 4);
	memcpy(&addr.sin_port, destination->port, 2);
#ifdef IO_WINDOWS
	DWORD ret = 0;
	DWORD flags = 0;
	WSABUF wsabuf;
	wsabuf.buf = (char *)buf;
	wsabuf.len = len;
	WSASendTo(iostate->fd[IO_FDID_UDPV4SOCKET].fd, &wsabuf, 1, NULL, flags, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), &iostate->overlapped_write[IO_FDID_UDPV4SOCKET], NULL);
	WSAGetOverlappedResult(iostate->fd[IO_FDID_UDPV4SOCKET].fd, &iostate->overlapped_write[IO_FDID_UDPV4SOCKET], &ret, TRUE, &flags);
#else
	int ret;
	ret = sendto(iostate->fd[IO_FDID_UDPV4SOCKET].fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
#endif
	if(ret > 0) {
		return ret;
	}
	else {
		return 0;
	}
}


// Receives an IPv4 UDP packet. Returns length of received message.
static int ioRecvUDPv4Packet(struct s_io_state *iostate, unsigned char *buf, const int len, struct s_io_v4addr *source) {
#ifdef IO_WINDOWS
	struct sockaddr_in *readaddr = (struct sockaddr_in *)&iostate->readaddr[IO_FDID_UDPV4SOCKET];
	int buflen = iostate->readbuf_len[IO_FDID_UDPV4SOCKET];
	if(buflen > 0) {
		iostate->readbuf_len[IO_FDID_UDPV4SOCKET] = 0;
		if(buflen < len) {
			memcpy(buf, &iostate->readbuf[(4096 * IO_FDID_UDPV4SOCKET)], buflen);
			memcpy(source->addr, &readaddr->sin_addr.s_addr, 4);
			memcpy(source->port, &readaddr->sin_port, 2);
			return buflen;
		}
		else {
			return 0;
		}
	}
	else {
		return 0;
	}
#else
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int ret = recvfrom(iostate->fd[IO_FDID_UDPV4SOCKET].fd, buf, len, 0, (struct sockaddr *)&addr, &addrlen);
	if(ret > 0) {
		memcpy(source->addr, &addr.sin_addr.s_addr, 4);
		memcpy(source->port, &addr.sin_port, 2);
	}
	return ret;
#endif
}


// Convert UDPv4 address to 24 bit address.
static void ioConvertAddressFromUDPv4(unsigned char *address, const struct s_io_v4addr *v4addr) {
	memset(address, 0, 24);
	address[0] = 1;
	address[1] = 4;
	address[2] = 1;
	memcpy(&address[4], v4addr->addr, 4);
	memcpy(&address[8], v4addr->port, 2);
}


// Get 24 bit address (UDP over IPv4 or IPv6) from hostname/port. Returns 1 if successful.
static int ioGetUDPAddress(struct s_io_state *iostate, unsigned char *address, const char *hostname, const char *port) {
	struct s_io_v4addr v4addr;
	struct s_io_v6addr v6addr;
	
	if((!(iostate->fd[IO_FDID_UDPV6SOCKET].fd < 0)) && (ioGetUDPv6Address(&v6addr, hostname, port))) {
		ioConvertAddressFromUDPv6(address, &v6addr);
		return 1;
	}
	if((!(iostate->fd[IO_FDID_UDPV4SOCKET].fd < 0)) && (ioGetUDPv4Address(&v4addr, hostname, port))) {
		ioConvertAddressFromUDPv4(address, &v4addr);
		return 1;
	}
	
	return 0;
}


// Send a packet and detect protocol using the 24 bit destination address. Returns length of sent message.
static int ioSendPacket(struct s_io_state *iostate, const unsigned char *buf, const int len, const unsigned char *destination) {
	struct s_io_v4addr v4addr;
	struct s_io_v6addr v6addr;

	switch(destination[0]) {
		case 1:
			// default protocol set
			switch(destination[1]) {
				case 6:
					// IPv6
					switch(destination[2]) {
						case 1:
							// UDP over IPv6
							memcpy(v6addr.addr, &destination[4], 16);
							memcpy(v6addr.port, &destination[20], 2);
							return ioSendUDPv6Packet(iostate, buf, len, &v6addr);
						break;
					}
				break;
				case 4:
					// IPv4
					switch(destination[2]) {
						case 1:
							// UDP over IPv4
							memcpy(v4addr.addr, &destination[4], 4);
							memcpy(v4addr.port, &destination[8], 2);
							return ioSendUDPv4Packet(iostate, buf, len, &v4addr);
						break;
					}
				break;
			}
			break;
	}
	
	return -1;
}


// Receive a packet and generate the 24 bit source address depending on the protocol. Returns length of received message.
static int ioRecvPacket(struct s_io_state *iostate, unsigned char *buf, const int len, unsigned char *source) {
	int ret;
	struct s_io_v4addr v4addr;
	struct s_io_v6addr v6addr;

	if((!(iostate->fd[IO_FDID_UDPV6SOCKET].fd < 0)) && ((ret = (ioRecvUDPv6Packet(iostate, buf, len, &v6addr))) > 0)) {
		// received UDP over IPv6
		ioConvertAddressFromUDPv6(source, &v6addr);
		return ret;
	}
	if((!(iostate->fd[IO_FDID_UDPV4SOCKET].fd < 0)) && ((ret = (ioRecvUDPv4Packet(iostate, buf, len, &v4addr))) > 0)) {
		// received UDP over IPv4
		ioConvertAddressFromUDPv4(source, &v4addr);
		return ret;
	}

	return -1;
}


// Wait for data.
static void ioWait(struct s_io_state *iostate, const int max_wait) {
#ifdef IO_WINDOWS
	// start reading UDPv4 socket
	DWORD udpv4recvlen;
	DWORD udpv4flags;
	udpv4flags = 0;
	WSABUF udpv4wsabuf;
	udpv4wsabuf.buf = (char *)&iostate->readbuf[(4096 * IO_FDID_UDPV4SOCKET)];
	udpv4wsabuf.len = 4096;
	iostate->readaddr_len[IO_FDID_UDPV4SOCKET] = sizeof(struct sockaddr_in);
	if((!(iostate->readbuf_used[IO_FDID_UDPV4SOCKET])) && (!(iostate->readbuf_len[IO_FDID_UDPV4SOCKET] > 0)) && (!(iostate->fd[IO_FDID_UDPV4SOCKET].fd < 0))) {
		iostate->readbuf_used[IO_FDID_UDPV4SOCKET] = 1;
		WSARecvFrom(iostate->fd[IO_FDID_UDPV4SOCKET].fd, &udpv4wsabuf, 1, NULL, &udpv4flags, &iostate->readaddr[IO_FDID_UDPV4SOCKET], &iostate->readaddr_len[IO_FDID_UDPV4SOCKET], &iostate->overlapped_read[IO_FDID_UDPV4SOCKET], 0);
	}
	
	// start reading TAP device
	DWORD tapreadlen;
	if((!(iostate->readbuf_used[IO_FDID_TAP])) && (!(iostate->readbuf_len[IO_FDID_TAP] > 0)) && (iostate->handle[IO_FDID_TAP] != INVALID_HANDLE_VALUE)) {
		iostate->readbuf_used[IO_FDID_TAP] = 1;
		ReadFile(iostate->handle[IO_FDID_TAP], &iostate->readbuf[(4096 * IO_FDID_TAP)], 4096, NULL, &iostate->overlapped_read[IO_FDID_TAP]);
	}
	
	// check for events
	WaitForMultipleObjects(IO_FDID_COUNT, iostate->event_read, FALSE, max_wait);
	if((iostate->readbuf_used[IO_FDID_UDPV4SOCKET]) && (!(iostate->readbuf_len[IO_FDID_UDPV4SOCKET] > 0)) && (!(iostate->fd[IO_FDID_UDPV4SOCKET].fd < 0))) {
		udpv4flags = 0; udpv4recvlen = 0;
		if(WSAGetOverlappedResult(iostate->fd[IO_FDID_UDPV4SOCKET].fd, &iostate->overlapped_read[IO_FDID_UDPV4SOCKET], &udpv4recvlen, FALSE, &udpv4flags) == TRUE) {
			iostate->readbuf_used[IO_FDID_UDPV4SOCKET] = 0;
			if(udpv4recvlen > 0) { 
				iostate->readbuf_len[IO_FDID_UDPV4SOCKET] = udpv4recvlen;
			}
		}
		else {
			if(WSAGetLastError() != WSA_IO_INCOMPLETE) {
				iostate->readbuf_used[IO_FDID_UDPV4SOCKET] = 0;
			}
		}
	}
	if((iostate->readbuf_used[IO_FDID_TAP]) && (!(iostate->readbuf_len[IO_FDID_TAP] > 0)) && (iostate->handle[IO_FDID_TAP] != INVALID_HANDLE_VALUE)) {
		tapreadlen = 0;
		if(GetOverlappedResult(iostate->handle[IO_FDID_TAP], &iostate->overlapped_read[IO_FDID_TAP], &tapreadlen, FALSE) != 0) {
			iostate->readbuf_used[IO_FDID_TAP] = 0;
			if(tapreadlen > 0) {
				iostate->readbuf_len[IO_FDID_TAP] = tapreadlen;
			}
		}
		else {
			if(GetLastError() != ERROR_IO_INCOMPLETE) {
				iostate->readbuf_used[IO_FDID_TAP] = 0;
			}
		}
	}
#elif defined(__APPLE__)
	fd_set fdset;
	struct timeval seltimeout;
	int i, fd;

	seltimeout.tv_sec = 1;
	seltimeout.tv_usec = 0;

	if (iostate->highdesc < 0)
	{
		FD_ZERO(&iostate->fdset);
		for (i = 0; i < IO_FDID_COUNT; i++)
		{
			if ((fd = iostate->fd[i].fd) >= 0)
			{
				FD_SET(fd, &(iostate->fdset));
				if (fd > iostate->highdesc)
				{
					iostate->highdesc = fd;
				}
			}
		}
		iostate->highdesc++;
	}
	FD_COPY(&(iostate->fdset), &fdset);

	int ret = select(iostate->highdesc, &fdset, NULL, NULL, &seltimeout);
#else
	poll(iostate->fd,IO_FDID_COUNT,max_wait);
#endif
}


// Initialize IO state.
static void ioCreate(struct s_io_state *iostate) {
#ifdef IO_WINDOWS
	WSADATA wsadata;
	WSAStartup(MAKEWORD(2,2), &wsadata);
#endif
	int i;
	for(i=0; i<IO_FDID_COUNT; i++) {
#ifdef IO_WINDOWS
		iostate->readbuf_len[i] = 0;
		iostate->readbuf_used[i] = 0;
		iostate->handle[i] = INVALID_HANDLE_VALUE;
		memset(&iostate->overlapped_read[i], 0, sizeof(OVERLAPPED));
		memset(&iostate->overlapped_write[i], 0, sizeof(OVERLAPPED));
		iostate->overlapped_read[i].hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
		iostate->overlapped_write[i].hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
		iostate->event_read[i] = iostate->overlapped_read[i].hEvent;
#else
		iostate->fd[i].events = 0;		
#endif
		iostate->fd[i].fd = -1;
	}
#ifdef __APPLE__
	iostate->highdesc = -1;
#endif
}


// Close all opened FDs.
static void ioReset(struct s_io_state *iostate) {
	int i;
	for(i=0; i<IO_FDID_COUNT; i++) {
		if(!(iostate->fd[i].fd < 0)) {
			close(iostate->fd[i].fd);
		}
	}
	ioCreate(iostate);
}


#endif // F_IO_C 
