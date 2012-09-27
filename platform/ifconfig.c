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


#ifndef F_IFCONFIG_C
#define F_IFCONFIG_C


#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#if defined(__FreeBSD__) || defined(__APPLE__)
#define IFCONFIG_BSD
#elif defined(WIN32)
#define IFCONFIG_WINDOWS
#elif defined(__linux__)
#define IFCONFIG_LINUX
#else Unknown platform
#endif


// Execute command.
static int ifconfigExec(const char *cmd) {
	int ret = system(cmd);
#ifdef IFCONFIG_DEBUG
	printf("executed=\"%s\", result=\"%d\"\n", cmd, ret);
#endif
	return ret;
}


// Check & copy input.
static int ifconfigCheckCopyInput(char *out, const int out_len, const char *in, const int in_len) {
	int i;
	char c;
	if(!(in_len < out_len)) return 0;
	i = 0;
	while(i < in_len) {
		c = in[i];
		if(!(c >= 32 && c < 127)) return 0;
		switch(c) {
			case ';':
			case '\'':
			case '\"':
			case '?':
			case '!':
			case '`':
				return 0;
		}
		i++;
	}
	memcpy(out, in, in_len);
	out[in_len] = '\0';
	return 1;
}


// Split input.
static int ifconfigSplit(char *a_out, const int a_len, char *b_out, const int b_len, const char *in, const int in_len, const char split_char) {
	int i;
	int s;
	if((a_len + 1 + b_len) < in_len) return 0;
	i = 0;
	s = 0;
	while(i < in_len) {
		if(in[i] == split_char) {
			s = i;
			break;
		}
		i++;
	}
	if(!(s > 0)) return 0;
	if(!ifconfigCheckCopyInput(a_out, a_len, &in[0], s)) return 0;
	if(!ifconfigCheckCopyInput(b_out, b_len, &in[(s + 1)], (in_len - (s + 1)))) return 0;
	return 1;
}


// Calculate netmask from prefixlen.
static void ifconfig4Netmask(char *out, const int prefixlen) {
	int mask[4];
	int i, j, p;
	for(j=0; j<4; j++) {
		mask[j] = 0;
	}
	p = prefixlen;
	j = 0;
	while(p > 0 && j < 4) {
		i = 0;
		while(p > 0 && i < 8) {
			mask[j] = (mask[j] | (1 << (8 - i - 1)));
			p--;
			i++;
		}
		j++;
	}
	snprintf(out, 16, "%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]);
}


// Configure IPv4 address on specified interface.
static int ifconfig4(const char *ifname, const int ifname_len, const char *addr, const int addr_len) {
	char cmd[1024]; memset(cmd, 0, 1024);
	char ifname_s[256]; memset(ifname_s, 0, 256);
	char ip_s[256]; memset(ip_s, 0, 256);
	char netmask_s[16]; memset(netmask_s, 0, 16);
	char prefixlen_s[4]; memset(prefixlen_s, 0, 4);
	int ret;
	
	if(!ifconfigCheckCopyInput(ifname_s, 256, ifname, ifname_len)) return 0;
	if(!ifconfigSplit(ip_s, 256, prefixlen_s, 4, addr, addr_len, '/')) return 0;
	if(strlen(prefixlen_s) == 0) memcpy(prefixlen_s, "32", 2);
	ret = 0; sscanf(prefixlen_s, "%d", &ret); ifconfig4Netmask(netmask_s, ret);
	
#if defined(IFCONFIG_WINDOWS)
	sprintf(cmd, "netsh interface ipv4 set address \"%s\" static \"%s\" \"%s\" store=active", ifname_s, ip_s, netmask_s); ret = ifconfigExec(cmd);
	if(ret == 0) {
		return 1;
	}
	
	sprintf(cmd, "netsh interface ip set address \"%s\" static \"%s\" \"%s\"", ifname_s, ip_s, netmask_s); ret = ifconfigExec(cmd);
	if(ret == 0) {
		return 1;
	}	
#elif defined(IFCONFIG_BSD)
	sprintf(cmd, "ifconfig \"%s\" up", ifname_s); ret = ifconfigExec(cmd);
	if(ret == 0) {
		sprintf(cmd, "ifconfig \"%s\" inet \"%s/%s\"", ifname_s, ip_s, prefixlen_s); ret = ifconfigExec(cmd);
		if(ret != 0) { return 0; }
		return 1;
	}	
#elif defined(IFCONFIG_LINUX)
	sprintf(cmd, "ip link set dev \"%s\" up", ifname_s); ret = ifconfigExec(cmd);
	if(ret == 0) {
		sprintf(cmd, "ip -4 addr flush dev \"%s\" scope global", ifname_s); ret = ifconfigExec(cmd);
		if(ret != 0) { return 0; }
		sprintf(cmd, "ip -4 addr add dev \"%s\" \"%s/%s\" broadcast + scope global", ifname_s, ip_s, prefixlen_s); ret = ifconfigExec(cmd);
		if(ret != 0) { return 0; }
		return 1;
	}
	
	sprintf(cmd, "ifconfig \"%s\" up", ifname_s); ret = ifconfigExec(cmd);
	if(ret == 0) {
		sprintf(cmd, "ifconfig \"%s\" \"%s\" netmask \"%s\"", ifname_s, ip_s, netmask_s); ret = ifconfigExec(cmd);
		if(ret != 0) { return 0; }
		return 1;
	}
#endif
	
	return 0;
}


// Configure IPv6 address on specified interface.
static int ifconfig6(const char *ifname, const int ifname_len, const char *addr, const int addr_len) {
	char cmd[1024]; memset(cmd, 0, 1024);
	char ifname_s[256]; memset(ifname_s, 0, 256);
	char ip_s[256]; memset(ip_s, 0, 256);
	char prefixlen_s[4]; memset(prefixlen_s, 0, 4);
	int ret;
	
	if(!ifconfigCheckCopyInput(ifname_s, 256, ifname, ifname_len)) return 0;
	if(!ifconfigSplit(ip_s, 256, prefixlen_s, 4, addr, addr_len, '/')) return 0;
	if(strlen(prefixlen_s) == 0) memcpy(prefixlen_s, "128", 2);

#if defined(IFCONFIG_WINDOWS)
	sprintf(cmd, "netsh interface ipv6 set address \"%s\" \"%s/%s\" store=active", ifname_s, ip_s, prefixlen_s); ret = ifconfigExec(cmd);
	return(ret == 0);
#elif defined(IFCONFIG_BSD)
	sprintf(cmd, "ifconfig \"%s\" up", ifname_s); ret = ifconfigExec(cmd);
	if(ret == 0) {
		sprintf(cmd, "ifconfig \"%s\" inet6 \"%s/%s\"", ifname_s, ip_s, prefixlen_s); ret = ifconfigExec(cmd);
		if(ret != 0) { return 0; }
		return 1;
	}	
#elif defined(IFCONFIG_LINUX)
	sprintf(cmd, "ip link set dev \"%s\" up", ifname_s); ret = ifconfigExec(cmd);
	if(ret == 0) {
		sprintf(cmd, "ip -6 addr flush dev \"%s\" scope global", ifname_s); ret = ifconfigExec(cmd);
		if(ret != 0) { return 0; }
		sprintf(cmd, "ip -6 addr add dev \"%s\" \"%s/%s\" scope global", ifname_s, ip_s, prefixlen_s); ret = ifconfigExec(cmd);
		if(ret != 0) { return 0; }
		return 1;
	}
#endif

	return 0;
}


#endif // F_IFCONFIG_C 
