#ifndef _vl_packet_
#define _vl_packet_

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>

class vl_packet
{
public:
	enum { header_length = 2 };
	enum { max_body_length = 2048 };

	vl_packet() : body_length_(0) { }

	const char *data() const
	{
		return data_;
	}

	char* data()
	{
		return data_;
	}

	std::size_t length() const
	{
		return header_length + body_length_;
	}

	const char* body() const
	{
		return data_ + header_length;
	}

	char* body() 
	{
		return data_ + header_length;
	}

	std::size_t body_length() const
	{
		return body_length_;
	}

	void body_length(std::size_t new_length)
	{
		body_length_ = new_length;
		if(body_length_ > max_body_length)
			body_length_ = max_body_length;
	}

	bool decode_header()
	{
		unsigned short header;
		memcpy(&header, data_, header_length);
		body_length_ = ntohs(header);
		if(body_length_ > max_body_length) {
			body_length_ = 0;
			return false;
		}

		return true;
	}

	void encode_header()
	{
		unsigned short header = body_length_;
		header = htons(header);
		memcpy(data_, &header, header_length);
	}

private:
	char data_[header_length + max_body_length];
	std::size_t body_length_;
};

typedef std::deque<vl_packet> vl_packet_queue;

#endif
