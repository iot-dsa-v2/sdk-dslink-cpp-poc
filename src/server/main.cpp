#include "server.hpp"
#include <cstdlib>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>

void WorkerThread(boost::shared_ptr<boost::asio::io_service> io_service) {
  std::stringstream ss;
  // ss << "[" << boost::this_thread::get_id() << "] Worker start"
  //           << std::endl;
  // std::cout << ss.str();

  while (true) {
    try {
      boost::system::error_code err;

      io_service->run(err);

      if (err) {
        ss.clear();
        ss << "[" << boost::this_thread::get_id() << "] Error: " << err
          << std::endl;
        std::cout << ss.str();
      } else {
        return;
      }
    } catch (std::exception &e) {
      ss.clear();
      ss << "[" << boost::this_thread::get_id()
        << "] Exception: " << e.what() << std::endl;
      std::cout << ss.str();
    }
  }

  ss.clear();
  ss << "[" << boost::this_thread::get_id() << "] Worker stop"
    << std::endl;
  std::cout << ss.str();
}

int main(int argc, char *argv[]) {
#ifdef USE_SSL
  std::cout << "Using secure TCP" << std::endl << std::endl;
#endif // USE_SSL

  try {
    int port;
    if (argc < 2) {
      port = 8080;
    } else {
      port = std::atoi(argv[1]);
    }


    boost::shared_ptr<boost::asio::io_service> io_service(
      new boost::asio::io_service);
    boost::shared_ptr<boost::asio::io_service::work> work(
      new boost::asio::io_service::work(*io_service));

    boost::thread_group worker_threads;
    for (int i = 0; i < 5; ++i) {
      worker_threads.create_thread(boost::bind(&WorkerThread, io_service));
    }

    Server s(io_service, port);

    worker_threads.join_all();
  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}