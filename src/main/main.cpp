#include "message.hpp"
#include "crypto.hpp"
#include <vector>
#include <iostream>

int main() {
	// dsa::message::factory mf;
	// dsa::message::basic_message* sub_msg_hdl = mf.new_message(dsa::message::MESSAGE_SUBSCRIBE);
	// sub_msg_hdl->do_something();

	// std::vector<uint8_t> salt = dsa::gen_salt(32);
	// std::cout << salt << std::endl;

	using namespace dsa::message;

	buffer_factory bf;
	// message_buffer& buf = bf.get_buffer();

	// buf.recycle();
	

	return 0;
}