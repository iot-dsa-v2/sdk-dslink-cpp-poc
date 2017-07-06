#include "connection.h"
#include "message.h"
#include "crypto.hpp"
#include <vector>
#include <iostream>

int main() {
	MessageFactory mf = MessageFactory();
	Message* sub_msg_hdl = mf.create_message(MSGTYPE_SUBSCRIBE);
	sub_msg_hdl->do_something();

	std::vector<byte> salt = dsa::gen_salt(32);
	std::cout << salt << std::endl;

	return 0;
}