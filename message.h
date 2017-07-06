#pragma once

#include <cstdio>
#include <cstddef>
#include <iostream>

using namespace std;

enum MessageType {
	MSGTYPE_SUBSCRIBE = 0,
	MSGTYPE_OBSERVE = 1,
	MSGTYPE_LIST = 2,
	MSGTYPE_INVOKE = 3,
	MSGTYPE_SET = 4
};

class SubscribeMessage;

class Message {
private:

public:
	static Message* create_message(MessageType message_type);
	virtual void do_something() = 0;

	virtual ~Message();
};

class SubscribeMessage : public Message {
	void do_something()
	{
		cout << "Subscribe::do_something" << endl;
	}
};


class MessageHeader {
};

class MessageFactory {
public:
	MessageFactory(const MessageFactory&) {}
	MessageFactory &operator=(const MessageFactory&) {}

	Message *pMessage;

//public:
	MessageFactory() { pMessage = NULL; }
	~MessageFactory() {
		if (pMessage) {
			cout << "~MessageFactory" << endl;
			delete pMessage;
			pMessage = NULL;
		}
	}

	Message *create_message(MessageType message_type) {
		pMessage = Message::create_message(message_type);
		return pMessage;
	}
};
