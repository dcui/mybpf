#!/usr/local/bin/bpftrace

#include <net/sock.h>

kprobe:tcp_v4_connect
/ pid == 5492 /
{
        $sk = (struct sock *)arg0;
	$uaddr = (struct sockaddr *uaddr)arg1;
	$addr_len = (int)arg2;

	printf("sk=%p, uaddr=%p, addr_len=%d\n", $sk, $uaddr, $addr_len);
#if 0
        $af = $sk->__sk_common.skc_family;
        $ulock = $sk->sk_lock.owned;
        //if ($af == AF_INET) {
        if ($ulock != 0) {
            $daddr = ntop($af, $sk->__sk_common.skc_daddr);
            $saddr = ntop($af, $sk->__sk_common.skc_rcv_saddr);
            $lport = $sk->__sk_common.skc_num;
            $dport = $sk->__sk_common.skc_dport; 
            $dport = ($dport >> 8) | (($dport << 8) & 0xff00);
            printf("%s %d %-15s %-5d -> %-15s %-5d, lock-owned: %d retval: %d\n",
                comm, tid, $saddr, $lport, $daddr, $dport, $ulock, retval);
        }
#endif
}

END {
}

