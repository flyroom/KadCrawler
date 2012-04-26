#pragma once

using boost::asio::ip::udp;

typedef void (__stdcall * asio_udpMessageHandler)(sockaddr_in & address, uint16 count, uint8 * data);

class AsioUDPServer
{
public:
	~AsioUDPServer(void);

	AsioUDPServer(boost::asio::io_service& service,unsigned int port):socket_(service, udp::endpoint(udp::v4(), port))
	{
		io_service = &service;
		udp_port = port;
		count = 0;
        error_count = 0;
        larget_unaccepted_count = 0;

		boost::asio::socket_base::receive_buffer_size option(8192*512);
		socket_.set_option(option);

		start_receive();
	}

	void handle_send(boost::shared_ptr<vector<unsigned char> > /*message*/,
      const boost::system::error_code& /*error*/,
      std::size_t /*bytes_transferred*/);
	

	void start_receive();
	void handle_receive(const boost::system::error_code& error,std::size_t /*bytes_transferred*/);

	bool send_to(const sockaddr_in & address, uint16 count, uint8 * data);

	udp::socket socket_;
	udp::endpoint remote_endpoint_;
	boost::array<unsigned char, 2048> recv_buffer_;
	boost::asio::io_service* io_service;

	boost::thread* ioThread;
	uint16 udp_port;
	unsigned long count;
    unsigned long error_count;
    unsigned long empty_count;
    unsigned long larget_unaccepted_count;
	int start(void);

};
