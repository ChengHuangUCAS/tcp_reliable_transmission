#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
#include <time.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it. seq=%d, rcv_end=%d, rcv_nxt=%d, seq_end=%d", 
			cb->seq, rcv_end, tsk->rcv_nxt, cb->seq_end);
		return 0;
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	switch (cb->flags) {
		case TCP_RST:
			// close connection immediately
			tcp_set_state(tsk, TCP_CLOSED);
			tcp_unset_retrans_timer(tsk);
			init_list_head(&tsk->retrans_timer.list);
			tcp_unhash(tsk);
			tcp_bind_unhash(tsk);
			break;

		case TCP_SYN:
			if (tsk->state == TCP_LISTEN) {
				// server: generate child sock
				struct tcp_sock *csk = alloc_tcp_sock();
				csk->sk_sip = cb->daddr;
				csk->sk_sport = cb->dport;
				csk->sk_dip = cb->saddr;
				csk->sk_dport = cb->sport;

				csk->iss = tcp_new_iss();
				csk->snd_nxt = csk->iss;
				csk->snd_una = csk->iss;

				csk->rcv_nxt = cb->seq_end;
				csk->rcv_wnd = ring_buffer_free(csk->rcv_buf);

				csk->parent = tsk;
				list_add_tail(&csk->list, &tsk->listen_queue);

				init_list_head(&csk->send_buf);
				init_list_head(&csk->rcv_ofo_buf);
				init_list_head(&csk->retrans_timer.list);
				init_list_head(&csk->timewait.list);

				tcp_set_state(csk, TCP_SYN_RECV);
				tcp_hash(csk);

				log(DEBUG, "tcp_process: create csk succeed");

				// server: reply handshake SYN|ACK

				tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);
			}
			break;

		case TCP_SYN | TCP_ACK:
			if (tsk->state == TCP_SYN_SENT) {
				if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt)) {
					// client: connection established
					tcp_unset_retrans_timer(tsk);
					init_list_head(&tsk->retrans_timer.list);
					struct pending_pkt *pkt = (struct pending_pkt *)tsk->send_buf.next;
					list_delete_entry(&pkt->list);
					free(pkt->packet);
					free(pkt);

					tsk->adv_wnd = cb->rwnd;
					tsk->cwnd = 1000;
					tsk->ssthresh = cb->rwnd / 2;
					tsk->dup_ack = 0;
					tsk->recovery_point = cb->ack - 1;
					tsk->inflight = 0;

					tsk->snd_wnd = cb->rwnd;
					tsk->snd_una = cb->ack;
					tsk->rcv_nxt = cb->seq_end;
					tcp_set_state(tsk, TCP_ESTABLISHED);

					wake_up(tsk->wait_connect);

					tcp_send_control_packet(tsk, TCP_ACK);
				} else {
					log(ERROR, "tcp_process: something wrong happened when receiving TCP_SYN|TCP_ACK");
				}

			} else if (tsk->state == TCP_ESTABLISHED) {
				// server: handshake ACK dropped, retransmit
				// tcp_send_control_packet(tsk, TCP_ACK);
				log(DEBUG, "tcp_process: ack of TCP_SYN|TCP_ACK packet lost, this shouldnt be a problem");
			}
			break;

		case TCP_ACK:
			if (tsk->state == TCP_SYN_RECV) {
				if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt)) {
					// server: connection established
					tcp_unset_retrans_timer(tsk);
					init_list_head(&tsk->retrans_timer.list);
					struct pending_pkt *pkt = (struct pending_pkt *)tsk->send_buf.next;
					list_delete_entry(&pkt->list);
					free(pkt->packet);
					free(pkt);

					// server: new sock to connect with client
					tcp_sock_accept_enqueue(tsk);
					tsk->snd_una = cb->ack;
					tsk->rcv_nxt = cb->seq_end;
					tcp_set_state(tsk, TCP_ESTABLISHED);
					log(DEBUG, "tcp_sock_read: free buffer: %d", ring_buffer_free(tsk->rcv_buf));

					// server: wake up parent sock to accept connection
					wake_up(tsk->parent->wait_accept);
				} else {
					log(ERROR, "tcp_process: something wrong happened when receiving TCP_ACK at state TCP_SYN_RECV");
				}

			} else if (tsk->state == TCP_FIN_WAIT_1) {
				// active close: FIN is received by passive close part
				if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt)) {
					if (cb->ack == tsk->snd_nxt) {
						tcp_unset_retrans_timer(tsk);
						init_list_head(&tsk->retrans_timer.list);
						tcp_set_state(tsk, TCP_FIN_WAIT_2);
					}
				} else {
					log(ERROR, "tcp_process: something wrong happened when receiving TCP_ACK at state TCP_FIN_WAIT_1");
					log(DEBUG, "una:%d, ack:%d, nxt:%d", tsk->snd_una, cb->ack, tsk->snd_nxt);
				}

			} else if (tsk->state == TCP_LAST_ACK) {
				// passive close: FIN is received by active close part, close
				tcp_unset_retrans_timer(tsk);
				init_list_head(&tsk->retrans_timer.list);
				tcp_set_state(tsk, TCP_CLOSED);
				if (!list_empty(&tsk->bind_hash_list))
					list_delete_entry(&tsk->bind_hash_list);
				if (!list_empty(&tsk->hash_list))
					list_delete_entry(&tsk->hash_list);
				free_tcp_sock(tsk);

			} else if (tsk->state == TCP_ESTABLISHED) {
				if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt)) {
				
					if (tsk->snd_una == cb->ack) {
						if (tsk->recovery_point <= cb->ack) {
							tsk->dup_ack++;
							if (tsk->dup_ack >= 2) {
								// fast recovery
								tsk->ssthresh = tsk->cwnd / 2;
								tsk->cwnd = tsk->ssthresh;
								tsk->adv_wnd = cb->rwnd;
								tsk->snd_wnd = min(tsk->adv_wnd, tsk->cwnd);
								tsk->recovery_point = tsk->snd_nxt;

								struct pending_pkt *pkt = (struct pending_pkt *)tsk->send_buf.next;
								char *packet = (char *)malloc(pkt->len);
								memcpy(packet, pkt->packet, pkt->len);
								// struct tcphdr *tcp = (struct tcphdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
								// log(DEBUG, "fast recovery: retransmit seq:%d, ack:%d, flag:%x", ntohl(tcp->seq), ntohl(tcp->ack), ntohl(tcp->flags));
								ip_send_packet(packet, pkt->len);
								tsk->dup_ack = 0;
								// pkt->retrans_time++;
							}
						}

					} else {
						// confirm new data
						tsk->dup_ack = 0;
						tsk->inflight -= (cb->ack - tsk->snd_una);

						tsk->adv_wnd = cb->rwnd;
						int mms = 1000;
						if (tsk->cwnd < tsk->ssthresh) {
							tsk->cwnd += cb->ack - tsk->snd_una;
						} else {
							tsk->cwnd += (mms * (cb->ack - tsk->snd_una) / tsk->cwnd);
						}
						// log(DEBUG, "tsk->cwnd:%d", tsk->cwnd);
						printf("%ld %d %d\n", clock(), tsk->cwnd, tsk->ssthresh);
						tsk->snd_wnd = min(tsk->adv_wnd, tsk->cwnd);
						tsk->snd_una = cb->ack;

						struct pending_pkt *tmp1, *tmp2;

						pthread_mutex_lock(&tsk->wait_send->lock);
						list_for_each_entry_safe(tmp1, tmp2, &tsk->send_buf, list) {
							struct tcphdr *tcp_hdr = (struct tcphdr *)((char *)packet_to_ip_hdr(tmp1->packet) + IP_BASE_HDR_SIZE);
							if (ntohl(tcp_hdr->seq) < cb->ack) {

								// log(DEBUG, "remove seq %d from send buffer", tcp_hdr->seq);
								
								list_delete_entry(&tmp1->list);
								// log(DEBUG, "free1");
								free(tmp1->packet);
								// log(DEBUG, "free2");
								free(tmp1);
							} else
								break;
						}
						pthread_mutex_unlock(&tsk->wait_send->lock);

						if (cb->ack < tsk->recovery_point) {
							struct pending_pkt *pkt = (struct pending_pkt *)tsk->send_buf.next;
							char *packet = (char *)malloc(pkt->len);
							memcpy(packet, pkt->packet, pkt->len);
							// struct tcphdr *tcp = (struct tcphdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
							// log(DEBUG, "fast recovery: retransmit seq:%d, ack:%d, flag:%x", ntohl(tcp->seq), ntohl(tcp->ack), ntohl(tcp->flags));
							ip_send_packet(packet, pkt->len);
							// pkt->retrans_time++;
						}

						if (&tmp1->list == &tsk->send_buf) {
							// log(DEBUG, "receive ACK: %d, clear retrans timer", cb->ack);
							tcp_unset_retrans_timer(tsk);
							init_list_head(&tsk->retrans_timer.list);
						} else {
							// log(DEBUG, "receive ACK: %d, reset retrans timer", cb->ack);
							tcp_set_retrans_timer(tsk);
						}

						wake_up(tsk->wait_send);
						// log(DEBUG, "wake up");
					}
					
					// log(DEBUG, "cb->ack:%d, rp:%d", cb->ack, tsk->recovery_point);	
					// if (cb->ack < tsk->recovery_point && tsk->snd_wnd - tsk->inflight > 0 && tsk->una < cb->ack) {
					// 	struct pending_pkt *pkt = (struct pending_pkt *)tsk->send_buf.next;

					// 	if (pkt->retrans_time == 3) {
					// 		tcp_unset_retrans_timer(tsk);
					// 		tcp_sock_close(tsk);
					// 	} else {
					// 		char *packet = (char *)malloc(pkt->len);
					// 		memcpy(packet, pkt->packet, pkt->len);

					// 		struct tcphdr *tcp = (struct tcphdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
					// 		log(DEBUG, "fast recovery: retransmit seq:%d, ack:%d, flag:%x", ntohl(tcp->seq), ntohl(tcp->ack), ntohl(tcp->flags));

					// 		ip_send_packet(packet, pkt->len);
					// 		pkt->retrans_time++;
					// 	}
					// }
				} else {
					log(DEBUG, "tcp_process: old TCP_ACK received, harmless, una:%d, ack:%d", tsk->snd_una, cb->ack);
				}
			}
			break;
		
		case TCP_FIN:
			if (tsk->rcv_nxt == cb->seq) {
				if (tsk->state == TCP_ESTABLISHED) {
					// passive close: 

					tsk->rcv_nxt = cb->seq_end;
					tcp_set_state(tsk, TCP_CLOSE_WAIT);
					tcp_send_control_packet(tsk, TCP_ACK);
					wake_up(tsk->wait_recv);
					// it's ok if this ack is dropped

				} else if (tsk->state == TCP_FIN_WAIT_2) {
					// active close: wait for timeout and then close
					tsk->rcv_nxt = cb->seq_end;
					tcp_set_state(tsk, TCP_TIME_WAIT);
					tcp_send_control_packet(tsk, TCP_ACK);
					tcp_set_timewait_timer(tsk);

				} else if (tsk->state == TCP_TIME_WAIT) {
					// ACK2 dropped, passive close
					tcp_send_control_packet(tsk, TCP_ACK);
					tcp_set_timewait_timer(tsk);

				} else if (tsk->state == TCP_FIN_WAIT_1) {
					// ACK1 dropped, active close
					tcp_set_state(tsk, TCP_FIN_WAIT_2);
					tcp_unset_retrans_timer(tsk);
					init_list_head(&tsk->retrans_timer.list);
					tsk->rcv_nxt = cb->seq_end;
					tcp_set_state(tsk, TCP_TIME_WAIT);
					tcp_send_control_packet(tsk, TCP_ACK);
					tcp_set_timewait_timer(tsk);
				} else if (tsk->state == TCP_CLOSE_WAIT) {
					// ACK1 dropped, passive close
					tcp_send_control_packet(tsk, TCP_ACK);
				} else if (tsk->state == TCP_LAST_ACK) {
					log(DEBUG, "this is really rare, and does no harm");
				}
			} else {
				struct ofo_pkt *pkt = (struct ofo_pkt *)malloc(sizeof(struct ofo_pkt));
				pkt->cb = (struct tcp_cb *)malloc(sizeof(struct tcp_cb));
				memcpy(pkt->cb, cb, sizeof(struct tcp_cb));
				list_add_tail(&pkt->list, &tsk->rcv_ofo_buf);
			}
			break;

		default:
			if (tsk->state == TCP_SYN_RECV) {
				tcp_set_state(tsk, TCP_ESTABLISHED);
				tcp_unset_retrans_timer(tsk);
				init_list_head(&tsk->retrans_timer.list);
				struct pending_pkt *pkt = (struct pending_pkt *)tsk->send_buf.next;
				list_delete_entry(&pkt->list);
				free(pkt->packet);
				free(pkt);
			}
			
			if (tsk->rcv_nxt == cb->seq) {
				// log(DEBUG, "receive:%d", cb->seq);
				char *data = cb->payload;

				pthread_mutex_lock(&tsk->wait_send->lock);
				write_ring_buffer(tsk->rcv_buf, data, cb->pl_len);
				tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
				pthread_mutex_unlock(&tsk->wait_send->lock);


				tsk->rcv_nxt = cb->seq_end;

				tcp_send_control_packet(tsk, TCP_ACK);

				// log(DEBUG, "search ofo buf");

				while (!list_empty(&tsk->rcv_ofo_buf)) {
					struct ofo_pkt *tmp1, *tmp2;
					int end = 0;
					list_for_each_entry_safe(tmp1, tmp2, &tsk->rcv_ofo_buf, list) {
						
						// log(DEBUG, "rcv_nxt %d, seq in ofo buf %d", tsk->rcv_nxt, tmp1->cb->seq);
						
						if (tmp1->cb->seq == tsk->rcv_nxt) {
							if (tmp1->cb->flags & TCP_FIN) {
								tcp_set_state(tsk, TCP_CLOSE_WAIT);
								end = 1;
								// it's ok if this ack is dropped
							} else {			
								pthread_mutex_lock(&tsk->wait_send->lock);
								write_ring_buffer(tsk->rcv_buf, tmp1->cb->payload, tmp1->cb->pl_len);
								tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
								pthread_mutex_unlock(&tsk->wait_send->lock);
								free(tmp1->cb->payload);
							}
							tsk->rcv_nxt = tmp1->cb->seq_end;
							// tcp_send_control_packet(tsk, TCP_ACK);
							list_delete_entry(&tmp1->list);
							free(tmp1->cb);
							free(tmp1);
							break;
						}
					}
					if (end == 1) {
						list_for_each_entry_safe(tmp1, tmp2, &tsk->rcv_ofo_buf, list) {
							list_delete_entry(&tmp1->list);
							free(tmp1->cb);
							free(tmp1);
						}
					}
					if (&tmp1->list == &tsk->rcv_ofo_buf)
						break;
				}
				tcp_send_control_packet(tsk, TCP_ACK);
				wake_up(tsk->wait_recv);


			} else if (tsk->rcv_nxt > cb->seq) {
				struct tcp_sock *tmp = (struct tcp_sock *)malloc(sizeof(struct tcp_sock));
				memcpy(tmp, tsk, sizeof(struct tcp_sock));
				tmp->rcv_nxt = cb->seq_end;
				tcp_send_control_packet(tmp, TCP_ACK);
				free(tmp);
			} else {
				// log(DEBUG, "out-of-order packet: ");
				// log(DEBUG, "expect: %d, receive:%d", tsk->rcv_nxt, cb->seq);
				struct ofo_pkt *pkt = (struct ofo_pkt *)malloc(sizeof(struct ofo_pkt));
				pkt->cb = (struct tcp_cb *)malloc(sizeof(struct tcp_cb));
				memcpy(pkt->cb, cb, sizeof(struct tcp_cb));
				pkt->cb->payload = (char *)malloc(cb->pl_len);
				memcpy(pkt->cb->payload, cb->payload, cb->pl_len);
				list_add_tail(&pkt->list, &tsk->rcv_ofo_buf);

				tcp_send_control_packet(tsk, TCP_ACK);
			}
	}
	
}
