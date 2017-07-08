#pragma once

#include <map>
#include <vector>
#include <array>
#include <boost/asio.hpp>

#include "message.hpp"

class connection;

using namespace dsa;
using namespace message;

class session {
public:
	session(boost::asio::io_service& io_service);

	/**
	 * in: new connection
	 * out: connection id
	 */
	int add_connection(connection* new_connection);

	/**
	 * in: connection id
	 * out: true if success
	 */
	bool remove_connection(int id);

	/**
	 * in: message
	 * out: true if message staged for write
	 */
	bool send_message(dsa::message::basic_message buf);

private:

	

	std::map<int, connection*> connections;
	boost::asio::io_service::strand strand;

	basic_message prepare_and_recycle_buf(buffer_factory::buffer& buf);

	buffer_factory::buffer& get_buffer();

	void incoming(buffer_factory::buffer &buf);

	friend connection;
};

