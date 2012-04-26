#pragma once
using boost::asio::ip::tcp;

class session
{
public:
	session(boost::asio::io_service& io_service):socket_(io_service)
	{
		
	}

	tcp::socket& socket()
	{
		return socket_;
	}

	void start();
private:
	void handle_read(const boost::system::error_code& error,size_t bytes_transferred);
	void handle_write(const boost::system::error_code& error);

	tcp::socket socket_;
	enum {max_length = 1024};
	char data_[max_length];
};

typedef boost::shared_ptr<boost::asio::ip::tcp::socket> SocketPtr;

class AsioTCPServer
{
public:
	~AsioTCPServer(void);

	AsioTCPServer(boost::asio::io_service& io_service,unsigned short port):io_service_(io_service),acceptor_(io_service,tcp::endpoint(tcp::v4(),port))
	{
		start_accept();
	}
	
	int start(void);
	void start_accept();
	void handle_accept(session* new_session,const boost::system::error_code& error);

	bool connect(string ip,unsigned short port);
	unsigned long send_sync(string ip,unsigned char* data,unsigned long len);
	unsigned long send_sync(unsigned long ip,unsigned char* data,unsigned long len);
	unsigned char* receive_sync(string ip, unsigned long* len);
	bool disconnect(string ip);

	boost::asio::io_service& io_service_;
	tcp::acceptor acceptor_;
	boost::thread* ioThread;

	map<unsigned long,SocketPtr> socket_pool;
};
