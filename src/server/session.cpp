#include "session.hpp"
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "connection.hpp";
Session::Session(Connection * connection)
  :connection(connection) {
  connection->socket().async_read_some(
    connection->get_read_buffer(),
    boost::bind(&Session::receive_request, this,
      boost::asio::placeholders::error,
      boost::asio::placeholders::bytes_transferred));
}

Session::~Session() {
  delete connection;
}
bool Session::send(boost::asio::const_buffer buffer) {
  return true;
}

void Session::receive_request(const boost::system::error_code &error,
  size_t bytes_transferred) {
  if (!error) {


    connection->socket().async_read_some(
      connection->get_read_buffer(),
      boost::bind(&Session::receive_request, this,
        boost::asio::placeholders::error,
        boost::asio::placeholders::bytes_transferred));
  } else {

    delete this;
  }
}