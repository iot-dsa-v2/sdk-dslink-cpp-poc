#include "message.hpp"
#include <iostream>

using namespace dsa;

message::basic_message* message::create_message(message::type message_type)
{
	switch (message_type) {
		case MESSAGE_SUBSCRIBE:
			return new message::subscribe_message();
		default:
			return nullptr;
	}
}

message::basic_message::~basic_message()
{
	std::cout << "~Message" << std::endl;
}

/****** buffer_factory ******/
using namespace message;

unsigned char* message_buffer::data() {
	return buf.data();
}

boost::asio::mutable_buffers_1 message_buffer::asio_buffer() {
	return boost::asio::buffer(buf, buf.max_size());
}

boost::asio::mutable_buffers_1 message_buffer::asio_buffer(int size) {
	return boost::asio::buffer(buf, size);
}