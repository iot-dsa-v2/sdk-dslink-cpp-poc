#include "message.hpp"

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