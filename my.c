#!/usr/local/bin/bpftrace

#include <net/sock.h>
#include <net/inet_sock.h>

kprobe:tcp_v4_connect
/ pid == 5492 /
{
        $sk = (struct sock *)arg0;
	$uaddr = (struct sockaddr *)arg1;
	$usin = (struct sockaddr_in *)arg1;
	$addr_len = arg2;

	$inet = (struct inet_sock *)$sk;
	$nexthop = $usin->sin_addr.s_addr;

	printf("sk=%p, addr_len=%d, %s:[0x%x]->%s:[0x%x]\n", $sk, $addr_len,
			ntop($inet->inet_saddr), $inet->inet_sport,
			ntop(AF_INET, $nexthop), $usin->sin_port);
}
