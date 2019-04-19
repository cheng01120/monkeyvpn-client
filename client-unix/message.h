#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char  BYTE;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint8_t  u8;

#define FALSE 0
#define TRUE  1
#define BOOL unsigned char

#define LZF_BUF_SIZE 2048 // max ethernet frame size
#define MAX_QUEUE_SIZE 81920

typedef struct {
	char data[MAX_QUEUE_SIZE];
	size_t length; // how many bytes is in buffer.
} buffer_t;

// move the data in buffer start from sz to the beginning.
int shift_buffer(buffer_t *buf, size_t sz)
{
	if(sz > buf->length) return -1;
	size_t left = buf->length - sz, moved = 0;
	while(1) {
		if(left > sz) {
			memmove(buf->data + moved, buf->data + sz + moved, sz);
			moved += sz;
			left -= sz;
		}
		else {
			memmove(buf->data + moved, buf->data + sz + moved,  left);
			break;
		}
	}
	// update buffer length
	buf->length -= sz;
}


typedef void (*recv_done_cb_t)(void); // callback when peer get到足够的数据。

typedef struct {
	int fd;
	char recv_buf[LZF_BUF_SIZE];
	int bytes_to_read;
	int bytes_read;

	recv_done_cb_t recv_done_cb;
} read_handler_t;

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
