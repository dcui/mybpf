#!/usr/local/bin/bpftrace

#include <net/sock.h>
#include <net/inet_sock.h>

/*
kprobe:tcp_v4_connect
/ pid == 5492 /
{
        $sk = (struct sock *)arg0;
	$uaddr = (struct sockaddr *)arg1;
	$usin = (struct sockaddr_in *)arg1;
	$net = sock_net(arg0);

	$inet = (struct inet_sock *)$sk;
	$nexthop = $usin->sin_addr.s_addr;

	printf("sk=%p, net=%p, %s:[0x%x]->%s:[0x%x]\n",
			$sk, $net,
			ntop($inet->inet_saddr), $inet->inet_sport,
			ntop(AF_INET, $nexthop), $usin->sin_port);
}
*/
kprobe:ip_route_output_key_hash
// / pid == 5492 /
{
	printf("pid=%d, comm=%s, net=%p\n", pid, comm, arg0);
}
