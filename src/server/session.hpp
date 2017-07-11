#pragma once

#include <map>
#include <vector>
#include <array>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include "message.hpp"

typedef uint8_t byte;

using namespace dsa::message;

class Connection;

class Session : public boost::enable_shared_from_this<Session> {
public:
  Session(Connection *);
  ~Session();
  bool send(boost::asio::const_buffer);

private:
  Connection * connection;
  std::atomic_bool should_stop;
  message_buffer buf;

  std::vector<uint32_t> subscriptionIds;
  void receive_request(message_buffer* buf,
	  const boost::system::error_code &err, size_t bytes_transferred);
  void read_some();
  bool parse_message(message_buffer* buf, size_t bytes_transferred, size_t offset);

  std::unique_ptr<boost::asio::deadline_timer> timer;
  void start_timer();
  bool on_timer(const boost::system::error_code &err);

  std::atomic_int sent_count;

  void send_response(uint32_t rid);
  void send_done(byte * buf, const boost::system::error_code & error, size_t bytes_transferred);
};

