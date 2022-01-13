#!/usr/local/bin/bpftrace

#include <net/sock.h>

kprobe:tcp_v4_connect
/ pid == 5492 /
{
        $sk = (struct sock *)arg0;
	$uaddr = (struct sockaddr *)arg1;
	$addr_len = arg2;

	printf("sk=%p, uaddr=%p, addr_len=%d\n", $sk, $uaddr, $addr_len);
}
