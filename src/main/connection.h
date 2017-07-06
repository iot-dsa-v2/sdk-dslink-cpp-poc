#pragma once

#include <boost/asio.hpp>

class Connection {
	bool send(boost::asio::const_buffer);
};

