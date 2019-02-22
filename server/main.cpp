#include "global.hpp"
#include <vector>
#include <string>
#include <algorithm>

using std::vector;
using std::string;


/*
认证过程：
Server发送public key to client
Client接收server public key, 发送自己的public key to server
Server用client的public key和自己的private key产生shared secret = 32 bytes
Client用server的public key和自己的private key产生shared secret = 32 bytes
Client和Server的shared secret相同

AES加密：
AES XOR_KEYLEN = 16bytes = 128bit
在每个消息的后面padding XOR_KEYLEN - message_len % XOR_KEYLEN
shared secret 32bytes, first 16 bytes is key, next 16 bytes is AES iv
*/

#define XOR_KEYLEN 32

//------------------------------------------------------------------------------------
//abstraction object for vl_tap and vl_session
//------------------------------------------------------------------------------------
class vl_participant : public std::enable_shared_from_this<vl_participant>
{
public:
	virtual void deliver(const vl_packet& packet) = 0;
	virtual void close() = 0;
	virtual string username() = 0;

	bool hw_addr_match(const char *dest_mac) {
		return !memcmp(dest_mac, mac_, 6);
	}

protected:
	vl_packet read_packet_;
	vl_packet_queue write_packets_;
	char mac_[64];
};

typedef std::shared_ptr<vl_participant> vl_participant_ptr;

//------------------------------------------------------------------------------------
// exchange data between sessions, manage online users, etc.
//------------------------------------------------------------------------------------
class session_manager
{
public:
	void join(vl_participant_ptr p)
	{
		vl_participants_.insert(p);
	}

	void leave(vl_participant_ptr p)
	{
		vl_participants_.erase(p);
	}

	void deliver(const vl_packet& packet)
	{
		// TODO: add mustcast address support.
		const char *dest_mac = packet.body(); // first 6 bytes of body is MAC address.
		bool is_broadcast = !memcmp(dest_mac, "\xff\xff\xff\xff\xff\xff", 6);

		for(auto participant : vl_participants_) {
			if(is_broadcast || participant->hw_addr_match(dest_mac))  {
				participant->deliver(packet);

				if(!is_broadcast) break;
			}
		}
	}

	bool user_exists(const string& username) {
		for(auto p : vl_participants_) {
			std::cout << "username: " << p->username() << "\n";
			if(p->username() == username) return true;
		}

		return false;
	}

private:
	std::set<vl_participant_ptr> vl_participants_;
};

session_manager g_manager;

//------------------------------------------------------------------------------------
// joining the local TAP device to session_manager
//------------------------------------------------------------------------------------
class vl_tap : public vl_participant
{
public:
	vl_tap(ba::io_service& ios, int fd) : tap_(ios, fd) { }

	string username() { return ""; }

	void start(const std::string& dev)
	{
		// Find the correspondent hw address of dev.
		struct ifaddrs *if_addrs, *if_start;
		int status;
		int i;

		if(getifaddrs(&if_start) == -1) {
			TRACE(VL_ERROR, "Error in getifaddrs(): %d %s", errno, strerror(errno));
			return;
		}
		if_addrs = if_start;
		while(if_addrs) {
			if(strncmp(dev.c_str(), if_addrs->ifa_name, dev.size()) == 0) {
				// Find interface with name 'dev'
				if(if_addrs->ifa_addr->sa_family == AF_PACKET) {
					struct sockaddr_ll * ll;

					ll = (struct sockaddr_ll *) if_addrs->ifa_addr;
					memcpy(mac_, ll->sll_addr, 6);
				} // AF_LINK
			} // strncmp
			if_addrs = if_addrs->ifa_next;
		} // while
		freeifaddrs(if_start);

		g_manager.join(shared_from_this());
		read_packet_from_device();
	}

	void close()
	{
		tap_.close();
		g_manager.leave(shared_from_this());
	}

	void deliver(const vl_packet& packet)
	{
		// write packet to tap device.
		bool write_in_progress = !write_packets_.empty();
		write_packets_.push_back(packet);

		if(!write_in_progress) {
			write_packet_to_device();
		}
	}


private:
	void read_packet_from_device()
	{
		auto self(shared_from_this());
		uint8_t buffer[ vl_packet::max_body_length ];
		tap_.async_read_some(ba::buffer(read_packet_.body(), vl_packet::max_body_length),
			[this, self](error_code ec, std::size_t length)
			{
				if(ec) {
					close();
					return;
				}

				read_packet_.body_length(length);
				read_packet_.encode_header();
				g_manager.deliver(read_packet_);

				read_packet_from_device();
			});
	}

	void write_packet_to_device()
	{
		auto self(shared_from_this());
		ba::async_write(tap_,
			ba::buffer(write_packets_.front().body(),
				write_packets_.front().body_length()),
			[this, self](error_code ec, std::size_t)
			{
				if(ec) {
					TRACE(VL_ERROR, "Unable to write packet to device: %s", ec2str(ec));
					close();
					return;
				}

				write_packets_.pop_front();
				if(!write_packets_.empty()) {
					write_packet_to_device();
				}
			});
	}

	ba::posix::stream_descriptor tap_;
};

//------------------------------------------------------------------------------------
// a session represents a conection from remote client.
//------------------------------------------------------------------------------------
class vl_session : public vl_participant
{
public:
	vl_session(tcp::socket socket) : socket_(std::move(socket))
	{
		auth_passed_ = 0;
		enable_lzf_  = true;
		username_ = "";
	}

	void start()
	{
		if (!uECC_make_key(server_pubkey_, server_privkey_, uECC_CURVE)) {
			TRACE(VL_ERROR, "Unable to make key!");
			close();
			return;
		}
		send_server_pub_key();
	}

	void close()
	{
		socket_.close();
		if(auth_passed_) {
			g_manager.leave(shared_from_this());
		}
	}

	void deliver(const vl_packet& packet)
	{
		unsigned int packet_len  = packet.body_length();
		uint8_t *pos             = (uint8_t *)packet.body();

		// LZF-compress the data.
		if(enable_lzf_) {
			packet_len  = lzf_compress(pos, packet_len, lzf_buf_, 2048);
			pos = lzf_buf_;
		}

		// xor encrypt.
		int m, n;
		for( m = 0; m < packet_len; m++) {
			n = m % XOR_KEYLEN;
			pos[m] ^= shared_secret_[n];
		}

		// create new packet.
		vl_packet pak;
		pak.body_length(packet_len);
		pak.encode_header();
		memcpy(pak.body(), pos, packet_len);

		bool write_in_progress = !write_packets_.empty();
		write_packets_.push_back(pak);
		if(!write_in_progress) {
			write_packet_to_network();
		}
	}

	string username() { return username_; }

private:
	void send_server_pub_key()
	{
		auto self(shared_from_this());
		ba::async_write(socket_, ba::buffer(server_pubkey_, 64),
			[this, self](error_code ec, std::size_t)
			{
				if(ec) {
					close();
					return;
				}

				read_client_pub_key();
			});
	}

	void read_client_pub_key()
	{
		auto self(shared_from_this());
		ba::async_read(socket_, ba::buffer(client_pubkey_, 64),
			[this, self](error_code ec, std::size_t)
			{
				if(ec) {
					close();
					return;
				}

				if(!uECC_valid_public_key(client_pubkey_, uECC_CURVE)) {
					close();
					return;
				}

				compute_shared_secret();
			});
	}

	void compute_shared_secret()
	{
		if(!uECC_shared_secret(
				client_pubkey_, server_privkey_, shared_secret_, uECC_CURVE)) {
			TRACE(VL_ERROR, "Unable to compute shared secret!");
			close();
			return;
		}

		read_id_header(); // read mac address/username/password.
	}

	void read_id_header()
	{
		auto self(shared_from_this());
		// read id length.
		// format of id packet:
		// 1 byte len(length of mac + user + "|" + pass) +
		// 1 byte flags +
		// 6 byte mac +
		// username + '|' + password
		ba::async_read(socket_, ba::buffer(mac_, 2),
			[this, self](error_code ec, std::size_t length)
			{
				if(ec) {
					close();
					return;
				}
				int id_len = mac_[0];
				int flags  = mac_[1];
				enable_lzf_ = flags ? true : false;
				if(enable_lzf_) {
					TRACE(VL_INFO, "LZF compression is enabled");
				}
				else {
					TRACE(VL_INFO, "LZF compression is disabled");
				}


				read_id_body(id_len);
			});
	}

	void read_id_body(int id_len)
	{
		auto self(shared_from_this());
		ba::async_read(socket_, ba::buffer(mac_, id_len),
			[this, self](error_code ec, std::size_t bytes_read)
			{
				if(ec) {
					TRACE(VL_ERROR, "Unable to read id content: %s", ec2str(ec));
					close();
					return;
				}

				// xor decrypt
				int m, n;
				for(m = 0; m < bytes_read; m++) {
					n = m % XOR_KEYLEN;
					mac_[m] ^= shared_secret_[n];
				}

				// extrace username and password.
				std::string user_and_pass(mac_ + 6, mac_ + bytes_read);
				std::size_t pos = user_and_pass.find('|');
				std::string user(mac_ + 6, mac_ + 6 + pos);
				std::string pass(mac_ + 6 + pos + 1, mac_ + bytes_read);
				// clear password from buffer.
				memset(mac_ + 6 + pos, 0x00, 64 - 6 - pos);

				uint8_t ret;
				ret = auth_sqlite3(user, pass);
				if(ret) {
					// auth passed, check if user is already online.
					if(g_manager.user_exists(user)) {
						ret = 0;
					}
					else {
						username_ = user;
						g_manager.join(shared_from_this());
					}
				}

				auth_passed_ = ret;
				send_auth_result();
			});
	}

	void send_auth_result()
	{
		auto self(shared_from_this());
		ba::async_write(socket_, ba::buffer(&auth_passed_, 1),
			[this, self](error_code ec, std::size_t)
			{
				if(ec || !auth_passed_) {
					close();
					return;
				}

				read_packet_header();
			});
	}

	void read_packet_header()
	{
		auto self(shared_from_this());
		ba::async_read(socket_,
			ba::buffer(read_packet_.data(), vl_packet::header_length),
			[this, self](error_code ec, std::size_t)
			{
				if(!ec && read_packet_.decode_header()) {
					read_packet_body();
				}
				else {
					TRACE(VL_ERROR, "Unable to read packet header: %s", ec2str(ec));
					close();
				}
			});
	}

	void read_packet_body()
	{
		auto self(shared_from_this());
		ba::async_read(socket_,
			ba::buffer(read_packet_.body(), read_packet_.body_length()),
			[this, self](error_code ec, std::size_t bytes_read)
			{
				if(ec) {
					TRACE(VL_ERROR, "Unable to read packet body: %s", ec2str(ec));
					close();
					return;
				}

				// decrypt the packet.

				unsigned packet_len = bytes_read;
				// xor decrypt
				unsigned m, n;
				char *pos = read_packet_.body();
				for(m = 0; m < packet_len; m++) {
					n = m % XOR_KEYLEN;
					pos[m] ^= shared_secret_[n];
				}

				if(enable_lzf_) {
					// decompress.
					packet_len = lzf_decompress(pos, packet_len, lzf_buf_, 2048);
					pos = (char *)lzf_buf_;

					//reset the packet.
					read_packet_.body_length(packet_len);
					read_packet_.encode_header();
					memcpy(read_packet_.body(), pos, packet_len);
				}

				g_manager.deliver(read_packet_);
				read_packet_header();
			});
	}

	void write_packet_to_network()
	{
		auto self(shared_from_this());
		ba::async_write(socket_,
			ba::buffer(write_packets_.front().data(),
				write_packets_.front().length()),
			[this, self](error_code ec, std::size_t)
			{
				if(ec) {
					close();
					return;
				}

				write_packets_.pop_front();
				if(!write_packets_.empty()) {
					write_packet_to_network();
				}
			});
	}

	tcp::socket socket_;
	uint8_t auth_passed_;
	uint8_t server_pubkey_[64], server_privkey_[32];
	uint8_t client_pubkey_[64], shared_secret_[32];
	uint8_t aes_buf_[2048], lzf_buf_[2048];
	bool enable_lzf_;
	string username_;
};

//------------------------------------------------------------------------------------
class vl_server {
public:
	vl_server(ba::io_service& io_service, const tcp::endpoint& endpoint, const std::string& dev)
		: acceptor_(io_service, endpoint),
		  socket_(io_service)
	{
		// open tap device.
		int tap_fd = -1;

#ifdef __linux__
		char if_name[IFNAMSIZ] = "";
		strncpy(if_name, dev.c_str(), dev.size());
		tap_fd = tun_alloc(if_name, IFF_TAP | IFF_NO_PI);
#elif __FreeBSD__
		std::string path("/dev/");
		path += dev;
		tap_fd = open(path.c_str(), O_RDWR);
#endif

		if(tap_fd < 0) {
			TRACE(VL_ERROR, "Unable to open TAP device!");
			return;
		}
		std::make_shared<vl_tap>(acceptor_.get_io_service(), tap_fd)->start(dev);

		do_accept();
	}

private:
	void do_accept()
	{
		acceptor_.async_accept(socket_,
			[this](error_code ec) {
				if(!ec) {
					std::make_shared<vl_session>(std::move(socket_))->start();
				}

				do_accept();
			});
	}

	tcp::acceptor acceptor_;
	tcp::socket socket_;
};

//------------------------------------------------------------------------------------
void usage() {
	std::cout << "Virtual LAN server.\n"
		<< "Usage: vl [ -p port ] [ -i interface ] [ -h ] [ -b ]\n"
		<< "-p <port>  port to listen on.\n"
		<< "-i <interface> TAP interface to bind to.\n"
		<< "-h print this help.\n"
		<< "-b run in background ( daemon mode ).\n";
	exit(1);
}

int main(int argc, char* argv[])
{
  int option;
  uint16_t port = 1226;
  char dev[64] = "tap0";
  bool daemonize = false;
  const char *pid_file = "/var/run/virtuallan.pid";
  int dev_found = 0;

  if(!db_exists()) {
	  std::cerr << "Unable to find user database!.\n";
	  exit(1);
  }

  while( (option = getopt(argc, argv, ":p:ihb")) > 0) {
	  switch(option) {
		  case 'b':
			  daemonize = true;
			  break;

		  case 'h':
			  usage();
			  break;

		  case 'p':
			  port = atoi(optarg);
			  break;

		  case 'i':
			  if(strlen(optarg) != 0) {
				  memset(dev, 0x00, 64);
				  snprintf(dev, 63, "%s", optarg);
			  }
			  break;

		  default:
			  printf("Unknown option %c\n", option);
			  break;
	  }
  }

  argv += optind;
  argc -= optind;

  // validate user intput.
  if( port > 65535 || port < 1) {
	  std::cerr << "Invalid listen port.\n";
	  exit(1);
  }

  /*
  std::regex e("tap[0-9]{1,3}");
  if(!std::regex_match(dev, e)) {
	  std::cerr << "Invalid TAP interface " << dev << "\n";
	  exit(1);
  }
  */

  struct ifaddrs *if_start, *if_addrs;
  if(getifaddrs(&if_start) < 0) {
	  std::cerr << "getifaddr(): " << strerror(errno) << "\n";
	  exit(1);
  }
  if_addrs = if_start;
  while(if_addrs) {
	if(strncmp(dev, if_addrs->ifa_name, strlen(dev)) == 0) {
		dev_found = 1;
		break;
	}
	if_addrs = if_addrs->ifa_next;
  }
  freeifaddrs(if_start);
  if(!dev_found) {
	  std::cerr << "Unable to find TAP device: " << dev << "\n";
	  exit(1);
  }

  try {
    ba::io_service io_service;
	tcp::endpoint endpoint(tcp::v4(), port);
	vl_server server(io_service, endpoint, dev);

	if(!daemonize) {
		io_service.run();
	}
	else {
		ba::signal_set signals(io_service, SIGINT, SIGTERM);
		signals.async_wait(
				boost::bind(&ba::io_service::stop, &io_service));
		io_service.notify_fork(ba::io_service::fork_prepare);
		if(pid_t pid = fork()) {
			if (pid > 0) {
				exit(0);
			}
			else {
				syslog(LOG_ERR | LOG_USER, "First fork failed: %m");
				return 1;
			}
		}
		setsid();
		chdir("/");
		umask(0);
		if(pid_t pid = fork()) {
			if(pid>0) {
				exit(0);
			}
			else {
				syslog(LOG_ERR | LOG_USER, "Second fork failed: %m");
				return 1;
			}
		}
		close(0);
		close(1);
		close(2);

		if(open("/dev/null", O_RDONLY) < 0) {
			syslog(LOG_ERR | LOG_USER, "Unable to open /dev/null: %m");
			return 1;
		}
		const char* output = "/tmp/vl.daemon.out";
		const int flags = O_WRONLY | O_CREAT | O_APPEND;
		const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
		if(open(output, flags, mode) < 0) {
			syslog(LOG_ERR | LOG_USER, "Unable to open %s: %m", output);
			return 1;
		}
		if(dup(1) <0) {
			syslog(LOG_ERR | LOG_USER, "Unable to dup output descriptor: %m");
			return 1;
		}

		// write the pid to file.
		FILE *fp = fopen(pid_file, "w");
		if(fp) {
			fprintf(fp, "%d", getpid());
			fclose(fp);
		}
		io_service.notify_fork(ba::io_service::fork_child);
		io_service.run();
	}
  }
  catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  // clean the pid file.
  if(daemonize) {
	  FILE *fp = fopen(pid_file, "r");
	  if(fp) {
		  fclose(fp);
		  unlink(pid_file);
	  }
  }
  return 0;
}
