#include "message.h"

Message* Message::create_message(MessageType message_type)
{
	if (message_type == MSGTYPE_SUBSCRIBE) {
		return new SubscribeMessage();
	}
	else {
		return NULL;
	}
}

Message::~Message()
{
	cout << "~Message" << endl;
}