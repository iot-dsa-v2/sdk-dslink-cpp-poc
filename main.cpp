#include "connection.h"
#include "message.h"

int main() {
	MessageFactory mf = MessageFactory();
	Message* sub_msg_hdl = mf.create_message(MSGTYPE_SUBSCRIBE);
	sub_msg_hdl->do_something();

	return 0;
}