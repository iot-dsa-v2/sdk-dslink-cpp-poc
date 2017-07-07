#include "connection.h"
#include "message.hpp"
#include "crypto.hpp"
#include <vector>
#include <iostream>

int main() {
	dsa::message::factory mf;
	dsa::message::basic_message* sub_msg_hdl = mf.new_message(dsa::message::MESSAGE_SUBSCRIBE);
	sub_msg_hdl->do_something();

	std::vector<byte> salt = dsa::gen_salt(32);
	std::cout << salt << std::endl;

	return 0;
}