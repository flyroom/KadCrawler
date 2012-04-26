#include "config.h"

typedef map<unsigned long,SocketPtr> socketMap;
typedef socketMap::iterator socketMapIt;

struct startIOServiceStruct
{
	startIOServiceStruct(boost::asio::io_service* s):service(s)
	{

	}
	void operator()()
	{
		service->run();
	}
	boost::asio::io_service* service;
};

void session::start()
{
	socket_.async_read_some(boost::asio::buffer(data_,max_length),
		boost::bind(&session::handle_read,this,
		boost::asio::placeholders::error,
		boost::asio::placeholders::bytes_transferred));
}

void session::handle_read(const boost::system::error_code& error,size_t bytes_transferred)
{
	if(!error)
	{
		boost::asio::async_write(socket_,
			boost::asio::buffer(data_,bytes_transferred),
			boost::BOOST_BIND(&session::handle_write,this,
			boost::asio::placeholders::error));
	}
	else
		delete this;
}

void session::handle_write(const boost::system::error_code& error)
{
	if(!error)
	{
		socket_.async_read_some(boost::asio::buffer(data_,max_length),
			boost::BOOST_BIND(&session::handle_read,this,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
	}
	else
		delete this;
}


AsioTCPServer::~AsioTCPServer(void)
{
}

void AsioTCPServer::start_accept()
{
	session* new_session = new session(io_service_);
	acceptor_.async_accept(new_session->socket(),
		boost::bind(&AsioTCPServer::handle_accept,this,new_session,
		boost::asio::placeholders::error));
}

void AsioTCPServer::handle_accept(session* new_session,const boost::system::error_code& error)
{
	if(!error)
	{
		new_session->start();
	}
	else
		delete new_session;
	start_accept();
}

int AsioTCPServer::start(void)
{
	ioThread = new boost::thread(startIOServiceStruct(&io_service_));
	start_accept();
	return 0;
}

bool AsioTCPServer::connect(string ip,unsigned short port)
{
	unsigned long ip_long;
	try
	{
		std::ostringstream stream;
		stream<<port;
		ip_long = inet_addr(ip.c_str());
		tcp::resolver resolver(io_service_);
		tcp::resolver::query query(ip,stream.str());
		tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

		SocketPtr pSocket(new boost::asio::ip::tcp::socket(io_service_));
#ifdef BOOST_1_47
		boost::asio::connect(*pSocket,endpoint_iterator);
#else
		boost::system::error_code error;
		pSocket->connect(*endpoint_iterator++, error);
		if (error)
			throw boost::system::system_error(error);
#endif
		socket_pool[ip_long]=pSocket;

	}
	catch (std::exception* e)
	{
		DEBUG_PRINT3("error in connecting with this ip %s , error: %s\n",ip.c_str(),e->what());
		return false;
	}
	catch(boost::exception & be)
	{
		DEBUG_PRINT2("%s",diagnostic_information(be).c_str());
		return false;
	}
	return true;
}

unsigned long AsioTCPServer::send_sync(string ip,unsigned char* data,unsigned long len)
{
	unsigned long ip_addr = inet_addr(ip.c_str());
	return send_sync(ip_addr,data,len);
}

unsigned long AsioTCPServer::send_sync(unsigned long ip,unsigned char* data,unsigned long len)
{
	socketMapIt it = socket_pool.find(ip);
	if(it == socket_pool.end())
	{
		DEBUG_PRINT2("send_sync error: connection with this ip not established %s",(inet_ntoa(*((in_addr*)&ip))));
		return 0;
	}

	boost::system::error_code ignored_error;
	SocketPtr pSocket = (SocketPtr)(it->second);
	try
	{
		boost::asio::write(*pSocket,boost::asio::buffer(data,len),boost::asio::transfer_all(),ignored_error);
	}
	catch (std::exception* e)
	{
		DEBUG_PRINT3("error in sending message to this ip %s , error: %s\n",inet_ntoa(*((in_addr*)&ip)),e->what());
		return 0;
	}
	return len;
}

unsigned char* AsioTCPServer::receive_sync(string ip, unsigned long* len)
{
	socketMapIt it = socket_pool.find(inet_addr(ip.c_str()));
	if(it == socket_pool.end())
	{
		DEBUG_PRINT2("receive_sync error: connection with this ip not established %s",ip.c_str());
		return 0;
	}

	boost::system::error_code error;
	SocketPtr pSocket = (SocketPtr)(it->second);
	static boost::array<unsigned char,1000> buf;
	buf.assign(0);
	try
	{
		*len = pSocket->read_some(boost::asio::buffer(buf),error);
	}
	catch (std::exception* e)
	{
		DEBUG_PRINT3("error in sending message to this ip %s , error: %s\n",ip.c_str(),e->what());
		*len = 0;
		return NULL;
	}
	return buf.c_array();
}

bool AsioTCPServer::disconnect(string ip)
{
	socketMapIt it = socket_pool.find(inet_addr(ip.c_str()));
	if(it != socket_pool.end())
	{

		socket_pool.erase(it);
	}
	return true;
}
