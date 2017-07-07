#pragma once

#include <cstdio>
#include <cstddef>
#include <iostream>

namespace dsa {
	namespace message {
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
			void do_something()
			{
				std::cout << "Subscribe::do_something" << std::endl;
			}
		};


		class header {
		};

		basic_message *create_message(type message_type);

		class factory {
		public:
			factory(const factory&) {}
			factory &operator=(const factory&) {}

			basic_message *pMessage;

		//public:
			factory() { pMessage = NULL; }
			~factory() {
				if (pMessage) {
					std::cout << "~factory" << std::endl;
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
