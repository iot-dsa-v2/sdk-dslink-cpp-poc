#pragma once

#include <boost/asio.hpp>

class session {
	bool send(boost::asio::const_buffer);
};

