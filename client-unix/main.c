// Simple example of client.
// Client prints received messages to stdout and sends from stdin.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

#include "uECC.h"
#include "uECC.c"

#include "lzf.h"
#include "lzf_c.c"
#include "lzf_d.c"

#include "tun_alloc.h" // allocate tun device.
#include "message.h"

#define uECC_CURVE uECC_secp256k1()
#define XOR_KEYLEN 32
#define MAX_CREDENTIAL_LEN 64

//#define SERVER_IPV4_ADDR "45.33.34.200"
#define SERVER_LISTEN_PORT 1226

void daemonize();
char error_message[64];
#define LOG_FILE "/tmp/mvpn-cli.log"
void perror(const char *message);
void log_message(const char *message);
void crypt_xor(char *buf, int buf_len);

// global variables.
peer_t   server;
tuntap_t tuntap;
fd_set read_fds, write_fds, except_fds;
char server_pub_key[64], shared_secret[32], client_identity[128];
char lzf_buf[LZF_BUF_SIZE];


//���������ȡ���ݺ��Ȼ�����tap_write_buf�У�Ȼ��ȴ�tap_fd��д�롣
char tap_write_buf[MAX_QUEUE_SIZE]; // buffer that holds data to be write to tap device.
size_t bytes_in_tap_buf = 0;

//����tap�ж�ȡ���ݺ��Ȼ�����peer_write_buf�У�Ȼ��ȴ�peer socket��д�롣
char peer_write_buf[MAX_QUEUE_SIZE];
size_t bytes_in_peer_buf = 0;

char if_name[IFNAMSIZ] = "tap0";
const char *username = "openwrt";
const char *password = "openwrt";
unsigned char MAC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

void read_packet_header(void);
void read_packet_body(void);

void shutdown_properly(int code);

void handle_signal_action(int sig_number)
{
	switch(sig_number) {
		case SIGINT:
			printf("Interrupt.\n");
			shutdown_properly(EXIT_SUCCESS);
			break;

		case SIGPIPE:
			shutdown_properly(EXIT_SUCCESS);
			break;

		default:
			break;
	}
}

int setup_signals()
{
  struct sigaction sa;
  sa.sa_handler = handle_signal_action;
  if (sigaction(SIGINT, &sa, 0) != 0) {
    perror("sigaction()");
    return -1;
  }
  if (sigaction(SIGPIPE, &sa, 0) != 0) {
    perror("sigaction()");
    return -1;
  }

  return 0;
}

int connect_server()
{
  int i;
  struct hostent *he;
  struct in_addr **addr_list;
  if( (he = gethostbyname("ovh")) == NULL) {
	  perror("gethostbyname");
	  return -1;
  }
  addr_list = (struct in_addr **)he->h_addr_list;
  /*
  for(i = 0; addr_list[i] != NULL; i++) {
  	printf("%s ", inet_ntoa(*addr_list[i]));
  }
  printf("\n");
  */

  // create socket
  server.socket = socket(AF_INET, SOCK_STREAM, 0);
  if (server.socket < 0) {
    perror("socket()");
    return -1;
  }

  // set up addres
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(inet_ntoa(*addr_list[0]));
  server_addr.sin_port = htons(SERVER_LISTEN_PORT);

  server.addres = server_addr;

  if (connect(server.socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) != 0) {
    perror("connect()");
    return -1;
  }
  printf("connected to server.\n");

  return 0;
}

int auth() {
	int i;
    ssize_t bytes_read = read(server.socket, server_pub_key, 64);
    if(bytes_read != 64) {
  	  perror("Read server public key");
	  return -1;
    }

    BYTE my_pub_key[64], my_priv_key[32]; // client DSA key pair.
    uECC_make_key(my_pub_key, my_priv_key, uECC_CURVE);
    uECC_shared_secret(
			(BYTE *)server_pub_key, my_priv_key, (BYTE *)shared_secret, uECC_CURVE);
	for(i = 0; i < 31; i++) {
		// printf("%02hhX", a);
		printf("%02x:", shared_secret[i] & 0xff);
	}
	printf("%02x\n", shared_secret[31] & 0xff);

	size_t bytes_written = write(server.socket, my_pub_key, 64);
	if(bytes_written != 64) {
		perror("Send client pub key");
		return -1;
	}

	// send identity to server.
	if(strlen(username) + strlen(password) > MAX_CREDENTIAL_LEN - (6 +1 + XOR_KEYLEN)) {
		//printf("Invalid username or password.\n");
		return -1;
	}
	char buf[2 + MAX_CREDENTIAL_LEN];

	printf("MAC: ");
	for(i = 0; i < 5; i++)
		printf("%02x:", MAC[i] & 0xff);
	printf("%02x\n", MAC[5] & 0xff);

	sprintf(buf + 2, "%s%s%s%s", MAC, username, "|", password);
	BYTE credential_len = 6 + strlen(username)  + 1 + strlen(password);
	printf("Credentail len: %d\n", credential_len);

	// xor encrypt the buffer
	crypt_xor(buf + 2, credential_len);

	buf[0] = credential_len;
	buf[1] = 1; // always enable LZF.
	bytes_written = write(server.socket, buf, 2 + credential_len);
	if(bytes_written != 2 + credential_len) {
		perror("Sending client identity to server");
		return -1;
	}

	// Read auth result.
	BYTE ret = 0;
	bytes_read = read(server.socket, &ret, 1);
	if(bytes_read != 1) {
		perror("Read auth result");
		return -1;
	}
	if(ret != 1)  { // authentication failed.
		printf("Authentication failed.\n");
		return -1;
	}

	printf("Auth OK.\n");

	server.bytes_to_read = 2; // header length: 2 bytes
	server.bytes_read = 0;
	server.recv_done_cb = &read_packet_header;

	return 0;
}

int build_fd_sets()
{
  FD_ZERO(&read_fds);
  FD_SET(tuntap.fd, &read_fds);
  FD_SET(server.socket, &read_fds);

	FD_ZERO(&write_fds);
	if(bytes_in_tap_buf > 0)
		FD_SET(tuntap.fd, &write_fds);
	if(bytes_in_peer_buf > 0)
		FD_SET(server.socket, &write_fds);


  FD_ZERO(&except_fds);
  FD_SET(tuntap.fd, &except_fds);
  FD_SET(server.socket, &except_fds);

  return 0;
}

/* Reads from tuntap and create new message. This message enqueues to send queueu. */
int handle_read_from_tuntap()
{
  int read_count = 0, write_count = 0;
  read_count = read(tuntap.fd, tuntap.recv_buf, LZF_BUF_SIZE);
  if (read_count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
    perror("Read from tuntap");
    return -1;
  }
  // if (read_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))��  donothing
	// if read_count == 0, do nothing
	if(read_count > 0) {
		//compress and encrypt the data read.
		u16 compressed_len = lzf_compress(tuntap.recv_buf, read_count, lzf_buf, LZF_BUF_SIZE);
		// xor encrypt
		crypt_xor(lzf_buf, compressed_len);

		memcpy(tuntap.recv_buf + 2, lzf_buf, compressed_len);
		u16 len = htons(compressed_len);
		memcpy(tuntap.recv_buf, &len, 2);

		// Copy to peer send buf.
		if(bytes_in_peer_buf + 2 + compressed_len > MAX_QUEUE_SIZE) {
			log_message("Peer write buffer overflow");
			return -1;
		}

		memcpy(peer_write_buf + bytes_in_peer_buf, tuntap.recv_buf, 2 + compressed_len);
		bytes_in_peer_buf += 2 + compressed_len;
	} // count > 0
  return 0;
}

void read_packet_header(void) {
	//printf("read_packet_header\n");
	u16 packet_len;
	memcpy(&packet_len, server.recv_buf, 2);
	packet_len = ntohs(packet_len);

	// read packet body.
	server.bytes_to_read = packet_len;
	server.bytes_read = 0;
	server.recv_done_cb = &read_packet_body; // when receive is done, enqueue the packet.
}

void read_packet_body(void) { //�Ѵ������ȡ�����ݴ�����save��tuntap��write buffer�С�
	//printf("read_packet_body");
	// xor decompress.
	crypt_xor(server.recv_buf, server.bytes_read);

	// decompress
	int decompressed_len = lzf_decompress(server.recv_buf, server.bytes_read, lzf_buf, LZF_BUF_SIZE);
	// write to tuntap.
	if( (bytes_in_tap_buf + decompressed_len) > MAX_QUEUE_SIZE) {
		log_message("TAP write buffer overflow.");
		shutdown_properly(EXIT_FAILURE);
	}
	//Copy to tap_write_buf�ȴ�д�뵽tap��
	memcpy(tap_write_buf + bytes_in_tap_buf, lzf_buf, decompressed_len);
	bytes_in_tap_buf += decompressed_len;

	// ׼����ȡ��һ��packet��
	server.bytes_to_read = 2; // �´ζ�ȡ2byte��header.
	server.bytes_read = 0;
	server.recv_done_cb = &read_packet_header;
}

/* Receive message from peer and handle it with message_handler(). */
int handle_read_from_peer()
{
	if(server.bytes_to_read <= 0) {
		printf("\"bytes_to_read\" invalid.\n");
		return -1;
	}

	ssize_t read_count;
	read_count = read(server.socket, server.recv_buf + server.bytes_read, server.bytes_to_read - server.bytes_read);
	if (read_count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		perror("handle_read_from_peer");
		return -1;
	}
	// if read_count < 0 && errno == EAGAIN or EWOULDBLOCK, do nothing.
	// if read_count == 0, do nothing.

	if(read_count > 0) {
		server.bytes_read += read_count;
		if(server.bytes_read != server.bytes_to_read) return 0; // Waiting for next reading.

		// read���㹻�����ݣ�����peer_recv_done_cb
		server.recv_done_cb();
	}

	return 0;
}


//��buf��buf_size bytes������д�뵽fd, ����buf_size����Ϊʣ�µ����ݳ��ȡ�
int handle_write(int fd, char *buf, size_t *buf_size) {
	ssize_t write_count = 0;
	write_count = write(fd, buf, *buf_size);

	if (write_count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		perror("Write to tuntap");
		return -1;
	}

	if(write_count > 0) {
		*buf_size -= write_count;

		//һ��û��д�ꡣ
		if(*buf_size != 0) {
			// ��ʣ�µ�����move��buffer��ʼ�ĵط���
			size_t left = *buf_size,  moved = 0;
			while(1) {
				if(left > write_count) {
					memmove(buf + moved, buf + write_count + moved, write_count);
					moved += write_count;
					left -= write_count;
				}
				else {
					memmove(buf + moved, buf + write_count + moved,  left);
					break;
				}
			} // while
		} // if
	} // if

	return 0;
}

/* You should be careful when using this function in multythread program.
 * Ensure that server is thread-safe. */
void shutdown_properly(int code)
{
	/*
	if(shutdown(server.socket, SHUT_RDWR) != 0) {
		perror("shutdown");
	}
	*/
	if(close(server.socket) != 0) {
		perror("close");
	}
	close(tuntap.fd);

    printf("Shutdown client properly.\n");
    exit(code);
}

int main(int argc, char **argv)
{
	//daemonize();
	memset(&tuntap, 0, sizeof(tuntap_t));
	memset(&server, 0, sizeof(peer_t));

    tuntap.fd = tun_alloc(if_name, IFF_TAP | IFF_NO_PI);
    if(tuntap.fd < 0) {
	  perror("Error open tap device");
	  exit(EXIT_FAILURE);
    }
	find_mac(if_name, MAC);
    //print_mac(MAC);

    /* Set nonblock for tap_fd. */
    int flag = fcntl(tuntap.fd, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(tuntap.fd, F_SETFL, flag);

	set_ip_address(if_name, "192.168.2.3");

  	if (setup_signals() != 0)
   	 exit(EXIT_FAILURE);

    if (connect_server() != 0) {
		log_message("Unable to connect");
        shutdown_properly(EXIT_FAILURE);
  	}

	if(auth() != 0) {
		shutdown_properly(EXIT_FAILURE);
	}

  int maxfd = server.socket;
  if(tuntap.fd > maxfd) maxfd = tuntap.fd;

  while (1) {
    // Select() updates fd_set's, so we need to build fd_set's before each select()call.
    build_fd_sets();

    int activity = select(maxfd + 1, &read_fds, &write_fds, &except_fds, NULL);

    switch (activity) {
      case -1:
        perror("select()");
        shutdown_properly(EXIT_FAILURE);

      case 0:
        // you should never get here
        printf("select() returns 0.\n");
        shutdown_properly(EXIT_FAILURE);

      default:
        /* All fd_set's should be checked. */
        if (FD_ISSET(tuntap.fd, &read_fds)) {
          if (handle_read_from_tuntap() != 0) {
			log_message("Error read from tuntap.");
            shutdown_properly(EXIT_FAILURE);
		  }
        }

		if (FD_ISSET(tuntap.fd, &write_fds))
		{
			if(handle_write(tuntap.fd, tap_write_buf, &bytes_in_tap_buf) != 0) {
				log_message("Error write to tuntap.");
				shutdown_properly(EXIT_FAILURE);
			}
		}

        if (FD_ISSET(tuntap.fd, &except_fds)) {
          printf("except_fds for tuntap.\n");
          shutdown_properly(EXIT_FAILURE);
        }

        if (FD_ISSET(server.socket, &read_fds)) {
          if (handle_read_from_peer() != 0) {
						printf("Error read from peer.\n");
            shutdown_properly(EXIT_FAILURE);
					}
        }

		if(FD_ISSET(server.socket, &write_fds)) {
			if(handle_write(server.socket, peer_write_buf, &bytes_in_peer_buf) != 0) {
				printf("Error write to peer.\n");
				shutdown_properly(EXIT_FAILURE);
			}
		}

        if (FD_ISSET(server.socket, &except_fds)) {
           printf("except_fds for server.\n");
           shutdown_properly(EXIT_FAILURE);
        }
    }// while 1
  }
  return 0;
}

void log_message(const char *message)
{
	printf("%s\n", message);
}

void crypt_xor(char *buf, int buf_len)
{
	int m, n;
	for(m = 0; m < buf_len; m++) {
		n = m % XOR_KEYLEN;
		buf[m] ^= shared_secret[n];
	}
}