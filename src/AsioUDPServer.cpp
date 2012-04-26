#include"config.h"
#include "KadScanner.h"

extern KadScanner scanner;

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

AsioUDPServer::~AsioUDPServer(void)
{
}



void AsioUDPServer::start_receive()
{
    socket_.async_receive_from(
        boost::asio::buffer(recv_buffer_,2048), remote_endpoint_,
        boost::bind(&AsioUDPServer::handle_receive, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
}

void AsioUDPServer::handle_receive(const boost::system::error_code& error,std::size_t bytes_recvd/*bytes_transferred*/)
{
    if (!error || bytes_recvd > 0)
    {
		boost::asio::ip::address addr = remote_endpoint_.address();
		unsigned short port = remote_endpoint_.port();
		
		//DEBUG_PRINT4("%s:  Incoming Packet,from  %s,port: %d\n",getCurrentTimeString().c_str(),addr.to_string().c_str(),port);
		
		sockaddr_in addr_param;
#ifdef WIN32
		addr_param.sin_addr.S_un.S_addr = htonl(addr.to_v4().to_ulong());
#else
		addr_param.sin_addr.s_addr = htonl(addr.to_v4().to_ulong());
#endif
		addr_param.sin_port = port;
		addr_param.sin_family = AF_INET;
		//addr_param.S_un.S_addr = addr.to_v4().to_ulong();
		if(bytes_recvd>2048)
		{
			std::ostringstream stream;
			stream<<"AsioUDPServer: packet length too long to process ,from node: ";
			stream<<addr.to_string().c_str()<<" "<<port;
			KadLogger::Log(WARN_KAD_LOG,stream.str());
            larget_unaccepted_count++;
		}
		else
		{
			try
			{
                scanner.processPacket(addr_param,bytes_recvd,recv_buffer_.c_array());
			}
			catch(string& error)
			{
				std::ostringstream stream;
				stream<<error<<" ";
				stream<<"from node ip "<<addr.to_string().c_str()<<" "<<port;
				KadLogger::Log(WARN_KAD_LOG,stream.str());
                error_count++;
			}
			catch (std::exception& e)
			{
				KadLogger::Log(WARN_KAD_LOG,e.what());
                error_count++;
			}
		}
		count++;
        if(count % 1000 == 0)
        {
            std::ostringstream stream;
            stream<<"Total Packets received amounts to a thousand : "<<count;
            DEBUG_PRINT2("%s\n",stream.str().c_str());
        }
    }
	else
	{
        empty_count++;    		
	}
	start_receive();
}

bool AsioUDPServer::send_to(const sockaddr_in & address, uint16 count, uint8 * data)
{
	try
	{
		udp::resolver resolver(*io_service);
		in_addr addr;
#ifdef WIN32
		addr.S_un.S_addr = address.sin_addr.S_un.S_addr;
#else
		addr.s_addr = address.sin_addr.s_addr;
#endif
		unsigned short remote_port = address.sin_port;
		udp::resolver::query query(udp::v4(),inet_ntoa(addr), boost::lexical_cast<string>(remote_port));
		udp::endpoint receiver_endpoint = *resolver.resolve(query);

		//udp::socket socket(*io_service, socket_.local_endpoint());
		
		boost::shared_ptr<vector<unsigned char> > bufferMsg(new vector<unsigned char>);
		for(int i=0;i<count;i++)
		{
			bufferMsg->push_back(data[i]);
		}
		if(data != NULL)
		{
			delete[] data;
			data = NULL;
		}

		socket_.async_send_to(boost::asio::buffer(*bufferMsg), 
			receiver_endpoint,
			boost::bind(&AsioUDPServer::handle_send,
				this,
				bufferMsg,
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred)
			);
	}
	catch(std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}
	
	return true;
}

void AsioUDPServer::handle_send(boost::shared_ptr<vector<unsigned char> > /*message*/,
      const boost::system::error_code& /*error*/,
      std::size_t /*bytes_transferred*/)
{ 
	
}
int AsioUDPServer::start(void)
{
	ioThread = new boost::thread(startIOServiceStruct(io_service));
	//ioThread->detach();
	return 0;
}
