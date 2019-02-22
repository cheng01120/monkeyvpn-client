#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char  BYTE;
typedef uint16_t u16;
typedef uint8_t  u8;


#define LZF_BUF_SIZE 2048
#define MAX_QUEUE_SIZE 81920

#define FALSE 0
#define TRUE  1
#define BOOL unsigned char


typedef void (*recv_done_cb_t)(void); // callback when peer get到足够的数据。

typedef struct {
	int fd;
	char recv_buf[LZF_BUF_SIZE];
	int bytes_to_read;
	int bytes_read;

	recv_done_cb_t recv_done_cb;
} read_handler_t;

typedef struct {
	int data_size; //data中已有数据的size
	int max_data_size; //最大的data size.
	char  *data; // 数据。
} queue_t;

queue_t* alloc_queue(int max_data_size)
{
	queue_t *queue = (queue_t *)malloc(sizeof(queue_t));
	queue->data_size = 0;
	queue->max_data_size = max_data_size;
	queue->data = (char *)malloc(max_data_size);

	return queue;
}

void dealloc_queue(queue_t *queue)
{
	free(queue->data);
	queue->data = NULL;
	free(queue);
}

//将buf中的数据添加到queue后面。
BOOL push(queue_t *queue, char *buf, int buf_size)
{
	if(queue->data_size + buf_size > queue->max_data_size) return FALSE;
	memcpy(queue->data + queue->data_size, buf, buf_size);
	queue->data_size += buf_size;
}

// 将queue中的数据向前移动n个byte
BOOL shift(queue_t *queue, int n)
{
	if(n > queue->data_size) return FALSE;

	int left = queue->data_size - n, moved = 0;
	while(1) {
		if(left > n) {
			memmove(queue->data + moved, queue->data + n + moved, n);
			moved += n;
			left -= n;
		}
		else {
			memmove(queue->data + moved, queue->data + n + moved,  left);
			break;
		}
	} // while
	queue->data_size -= n;
	return TRUE;
}

// local ---------------------------------------------------------------------
typedef struct {
	int fd;
	char recv_buf[LZF_BUF_SIZE];
} tuntap_t;

// peer -----------------------------------------------------------------------

typedef struct {
    int    socket;
    struct sockaddr_in addres;

    char recv_buf[LZF_BUF_SIZE];

	unsigned short bytes_to_read; // the next packet length to be read from peer.
	unsigned short bytes_read; // how many bytes has been read for this packet.
	recv_done_cb_t recv_done_cb;

} peer_t;
// common ---------------------------------------------------------------------

#endif /* MESSAGE_H */
