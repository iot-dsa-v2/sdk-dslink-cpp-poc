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

buffer_factory::buffer_factory() : free_buffers() {}

buffer_factory::buffer::buffer(buffer_factory &f, int key)
	: factory(f), id(key) {}

unsigned char* buffer_factory::buffer::data() {
	return buf.data();
}
			
void buffer_factory::buffer::recycle() {
	factory.free_buffers.push_back(id);
	std::cout << "recycle: " << factory.free_buffers.size() << std::endl;
}

boost::asio::mutable_buffers_1 buffer_factory::buffer::asio_buffer() {
	return boost::asio::buffer(buf, buf.max_size());
}

boost::asio::mutable_buffers_1 buffer_factory::buffer::asio_buffer(int size) {
	return boost::asio::buffer(buf, size);
}

buffer_factory::buffer& buffer_factory::get_buffer() {
	std::cout << "get: " << free_buffers.size() << std::endl;
	if (free_buffers.empty()) {
		int key = buffer_count++;
		buffers[key] = std::unique_ptr<buffer>(new buffer(*this, key));
		return *buffers.at(key);
	}
	int key = free_buffers.back();
	free_buffers.pop_back();
	return *buffers.at(key);
}	
