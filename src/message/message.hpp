#pragma once

#include <array>
#include <atomic>
#include <vector>
#include <cstddef>
#include <cstdio>
#include <iostream>
#include <map>
#include <memory>
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>

namespace dsa {
namespace message {
/****** BUFFER FACTORY ******/
class buffer_factory {
public:
	enum { max_length = 4096 };

	class buffer {
	private:
		std::array<unsigned char, max_length> buf;
		buffer_factory &factory;
		int id;

	public:
		buffer(buffer_factory &f, int key);

		operator std::array<unsigned char, max_length>() { return buf; }
		inline unsigned char& operator[] (int idx) { return buf[idx]; }
		boost::asio::mutable_buffers_1 asio_buffer();
		boost::asio::mutable_buffers_1 asio_buffer(int size);

		unsigned char *data();

		int max_size() const { return buf.max_size(); }

		void recycle();
	};

	buffer_factory();

	buffer& get_buffer();

private:

	std::atomic_int buffer_count;
	std::map<int, std::unique_ptr<buffer>> buffers;
	std::vector<int> free_buffers;
};

typedef buffer_factory::buffer message_buffer;

enum {
  max_message_length = 4096
};

/****** MESSAGES ******/
enum type {
  MESSAGE_SUBSCRIBE = 0,
  MESSAGE_OBSERVE = 1,
  MESSAGE_LIST = 2,
  MESSAGE_INVOKE = 3,
  MESSAGE_SET = 4
};

class basic_message {
private:
public:
  virtual void do_something() = 0;

  virtual ~basic_message();
};

class subscribe_message : public basic_message {
  void do_something() { std::cout << "Subscribe::do_something" << std::endl; }
};

/****** HEADER ******/
class header {};

/****** CREATE MESSAGE ******/
basic_message *create_message(type message_type);

/****** MESSAGE FACTORY ******/
class message_factory {
public:
  message_factory(const message_factory &) {}
  message_factory &operator=(const message_factory &) {}

  basic_message *pMessage;

  // public:
  message_factory() { pMessage = NULL; }
  ~message_factory() {
    if (pMessage) {
      std::cout << "~message_factory" << std::endl;
      delete pMessage;
      pMessage = NULL;
    }
  }

  basic_message *new_message(type message_type) {
    pMessage = create_message(message_type);
    return pMessage;
  }
};
}
}
