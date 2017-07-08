#include "session.hpp"
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "connection.hpp";
#include "server.hpp";
Session::Session(Connection * connection)
  :connection(connection) {
  //async_read(connection->socket(), connection->get_read_buffer(), boost::bind(&Session::receive_request, this,
  //  boost::asio::placeholders::error,
  //  boost::asio::placeholders::bytes_transferred));
  read_some();
}

Session::~Session() {
  delete connection;
}
bool Session::send(boost::asio::const_buffer buffer) {
  return true;
}

void Session::read_some() {
  connection->socket().async_read_some(
    connection->get_read_buffer(),
    boost::bind(
      &Session::receive_request,
      this,
      boost::asio::placeholders::error,
      boost::asio::placeholders::bytes_transferred
    )
  );
}
void Session::receive_request(const boost::system::error_code &error,
  size_t bytes_transferred) {
  if (!error) {
    if (!parse_message(bytes_transferred)) {
      delete this;
      return;
    }
    read_some();
  } else {
    delete this;
  }
}

bool Session::parse_message(size_t bytes_transferred) {
  byte *cur = connection->read_buf;
  uint32_t size;
  uint16_t header_size;
  byte method_type;
  uint32_t rid;
  memcpy(&size, cur, sizeof(size));
  cur += sizeof(size);
  memcpy(&header_size, cur, sizeof(header_size));
  cur += sizeof(header_size);
  memcpy(&method_type, cur, sizeof(method_type));
  cur += sizeof(method_type);
  memcpy(&rid, cur, sizeof(rid));
  cur += sizeof(rid);
  // ignore dynamic headers for now

  if (bytes_transferred == size) {
    subscriptionIds.push_back(rid);
    start_timer();
    return true;
  }
  return false;
}

void Session::start_timer() {
  static boost::posix_time::milliseconds interval(100);

  if (timer.get() == nullptr) {
    timer.reset(new boost::asio::deadline_timer(*(connection->serv.io_service), interval));
    (*timer).async_wait(boost::bind(
      &Session::on_timer,
      this,
      boost::asio::placeholders::error
    ));
  }
}
bool Session::on_timer(const boost::system::error_code &err) {
  start_timer();
  return true;
}