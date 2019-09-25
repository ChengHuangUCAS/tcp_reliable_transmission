#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"
#include "log.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	struct tcp_timer *tmp1, *tmp2;
	// log(DEBUG, "scan begin");
	list_for_each_entry_safe(tmp1, tmp2, &timer_list, list) {
		if (tmp1->enable) {
			// refresh timer
			tmp1->timeout -= TCP_TIMER_SCAN_INTERVAL;
			// log(DEBUG, "tmp1->timeout:%d", tmp1->timeout);

			if (tmp1->enable && tmp1->timeout <= 0) {
				// timeout
				if (tmp1->type == 0) {
					log(DEBUG, "timeout");
					tmp1->enable = 0;
					if (!list_empty(&tmp1->list))
						list_delete_entry(&tmp1->list);

					struct tcp_sock *tsk = timewait_to_tcp_sock(tmp1);
					tcp_set_state(tsk, TCP_CLOSED);
					if (!list_empty(&tsk->bind_hash_list))
						list_delete_entry(&tsk->bind_hash_list);
					if (!list_empty(&tsk->hash_list))
						list_delete_entry(&tsk->hash_list);
					free_tcp_sock(tsk);
				} else {
					//TODO: retransmit
					log(DEBUG, "retransmit, tmp1->timeout:%d", tmp1->timeout);
					struct tcp_sock *tsk = retranstimer_to_tcp_sock(tmp1);
					int mms = 1000;
					tsk->ssthresh = tsk->cwnd / 2;
					tsk->cwnd = mms;
					if (!list_empty(&tsk->send_buf)) {
						struct pending_pkt *pkt = (struct pending_pkt *)tsk->send_buf.next;
						if (pkt->retrans_time == 3) {
							tcp_unset_retrans_timer(tsk);
							tcp_sock_close(tsk);
						} else {
							char *packet = (char *)malloc(pkt->len);
							memcpy(packet, pkt->packet, pkt->len);

							struct tcphdr *tcp = (struct tcphdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
							log(DEBUG, "retransmit seq:%d, ack:%d, flag:%x", ntohl(tcp->seq), ntohl(tcp->ack), ntohl(tcp->flags));

							ip_send_packet(packet, pkt->len);
							pkt->retrans_time++;
							tmp1->timeout = TCP_RETRANS_INTERVAL_INITIAL;
							for (int i = pkt->retrans_time; i > 0; i--)
								tmp1->timeout *= 2;
						}
					}
				}
			}
		} else {
			// if (!list_empty(&tmp1->list))
			// 	list_delete_entry(&tmp1->list);
		}
	}
	// log(DEBUG, "scan end");
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	tsk->timewait.type = 0;
	tsk->timewait.enable = 1;
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
	
	if (!timer_list.next || !timer_list.prev)
		init_list_head(&timer_list);
	if (list_empty(&tsk->timewait.list))
		list_add_tail(&tsk->timewait.list, &timer_list);
}

// set the retrans timer of a tcp sock, by adding the timer into timer_list
void tcp_set_retrans_timer(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	tsk->retrans_timer.type = 1;
	tsk->retrans_timer.enable = 1;
	tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	// printf("retrans_timer.list:%x, next: %x, prev: %x\n", &tsk->retrans_timer.list, tsk->retrans_timer.list.next, tsk->retrans_timer.list.prev);
	
	if (!timer_list.next || !timer_list.prev)
		init_list_head(&timer_list);
	// printf("timer_list:%x, next: %x, prev: %x\n", &timer_list, timer_list.next, timer_list.prev);
	if (list_empty(&tsk->retrans_timer.list))
		list_add_tail(&tsk->retrans_timer.list, &timer_list);
}

// unset the retrans timer of a tcp sock, by removing the timer from timer_list
void tcp_unset_retrans_timer(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	tsk->retrans_timer.enable = 0;
	if (!list_empty(&tsk->retrans_timer.list))
		list_delete_entry(&tsk->retrans_timer.list);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
