#include"config.h"
#include"KadUtil.h"
#include"KadScanner.h"
#include"KadClientCredits.h"
#include"FileClientSession.h"
#include"KadFileDownloader.h"
#include"KadCrawleManager.h"
#include"DatabaseLogger.h"

using namespace KadCrawl;

KadCrawleManager::KadCrawleManager(void)
{
	scanner = NULL;
}
KadCrawleManager::~KadCrawleManager(void)
{
}
unsigned long KadCrawleManager::scanWithPing()
{
	if(scanner == NULL)
		return 0;
	list<KadNode> nodeList = scanner->GetUnRequestedNodeList();
	list<KadNode>::iterator it;
	for(it = nodeList.begin();it != nodeList.end();it++)
	{
		KadNode& tnode = *it;
		scanner->sendPingProbe(tnode);
	}
	return 0;
}
unsigned long KadCrawleManager::scanWithHelloReq()
{
	if(scanner == NULL)
		return 0;
	list<KadNode> nodeList = scanner->GetUnRequestedNodeList();
	char ipTargetStr[] = "192.168.1.126";
	unsigned long src_addr = inet_addr("192.168.1.116");
	unsigned long target_addr = inet_addr(ipTargetStr);

	KadNode target_node;
	unsigned long target_id_bytes[4]={
		3179235593UL,
		443396052UL,
		3215202336UL,
		1450183149UL
	};
	CUInt128 target_id;
	target_id.directAssign(target_id_bytes[0],
		target_id_bytes[1],
		target_id_bytes[2],
		target_id_bytes[3]
	);
	target_node.kad_id = target_id;
	target_node.ipNetOrder = target_addr;
	target_node.udp_port = 41218;
	target_node.tcp_port = 58699;
	nodeList.push_front(target_node);

	list<KadNode>::iterator it;
	for(it = nodeList.begin();it != nodeList.end();it++)
	{
		KadNode& tnode = *it;
		scanner->SendMyDetails(KADEMLIA2_HELLO_REQ,tnode,false,tnode.version);
	}
    DEBUG_PRINT1("Scan with HELLO_REQ Complete\n");
	return 0;
}
unsigned long KadCrawleManager::scanWithHelloReqUseSybils(uint8 zone_prefix)
{
	if(scanner == NULL)
		return 0;
    KadNode sybil_node;
    sybil_node.kad_id = KadCrawl::KadUtil::kad_id;
    sybil_node.udp_port = KadCrawl::KadUtil::udp_port;
	list<KadNode> nodeList = scanner->GetUnRequestedNodeList();
	list<KadNode>::iterator it;
	for(it = nodeList.begin();it != nodeList.end();it++)
	{
		KadNode& tnode = *it;
        uint8 zone_prefix_local = tnode.kad_id.GetByteChunk(0);
        if(zone_prefix_local!=zone_prefix)
            continue;
		scanner->SendDetailsWithIdentity(KADEMLIA2_HELLO_REQ,tnode,sybil_node,false,tnode.version);
	}
    DEBUG_PRINT1("Scan with HELLO_REQ Sybils Complete\n");
	return 0;
}

unsigned long KadCrawleManager::updateNodesByMixedReq(unsigned long delay_between_packets_mseconds,const KadFilter& pass_filter,const KadFilter& block_filter)
{
    if(scanner == NULL)
		return 0;
	list<KadNode> nodeList = scanner->GetUnRequestedNodeList();
	list<KadNode>::iterator it;
	for(it = nodeList.begin();it != nodeList.end();it++)
	{
        KadNode& tnode = *it;
        if(!KadCrawl::KadUtil::checkFilter(tnode,pass_filter))
            continue;
        if(!KadCrawl::KadUtil::checkOrBlockFilter(tnode,block_filter))
            continue;
        //scanner->sendBootstrapReq(tnode);
        scanner->sendNodeLookupReq(tnode.kad_id,tnode,20);
        CUInt128 inverted_id = tnode.kad_id;
        if(tnode.kad_id.GetBitNumber(0))
        {
            inverted_id.SetBitNumber(0,0);
        }
        else
        {
            inverted_id.SetBitNumber(0,1);
        }
        if(delay_between_packets_mseconds!=0)
        {
            kad_wait_ms(delay_between_packets_mseconds);
        }
        scanner->sendNodeLookupReq(inverted_id,tnode,20);
    }
	return 0;
}
unsigned long KadCrawleManager::updateNodesByBootstrapReq(unsigned int version)
{
	if(scanner == NULL)
		return 0;

	list<KadNode> nodeList = scanner->GetUnRequestedNodeList();
	list<KadNode>::iterator it;
	for(it = nodeList.begin();it != nodeList.end();it++)
	{
		KadNode& tnode = *it;
        if(version == 1)
        {
            scanner->SendMyDetails(KADEMLIA_BOOTSTRAP_REQ_DEPRECATED,tnode,false,version);
        }
        else if(version == 2)
        {
            scanner->sendBootstrapReq(tnode);
        }
	}
	return 0;
}
unsigned long KadCrawleManager::updateNodesBySampleBootstrapReq(unsigned int version,unsigned long sample_rate)
{
	if(scanner == NULL)
		return 0;
	list<KadNode> nodeList = scanner->GetUnRequestedNodeList();

    if(sample_rate > 100)
        sample_rate = 100;
    else if(sample_rate < 0)
        sample_rate = 0;
    unsigned long sample_size = (double)nodeList.size()*((double)sample_rate/(double)100);
    nodeList = KadCrawl::KadUtil::extractRandomSetFromNodeList(nodeList,sample_size);
	list<KadNode>::iterator it;
	for(it = nodeList.begin();it != nodeList.end();it++)
	{
		KadNode& tnode = *it;
        if(version == 1)
        {
            scanner->SendMyDetails(KADEMLIA_BOOTSTRAP_REQ_DEPRECATED,tnode,false,version);
        }
        else if(version == 2)
        {
            scanner->sendBootstrapReq(tnode);
        }
	}
	return 0;
}

unsigned long KadCrawleManager::updateNodesByBootstrapReqPeriodically(unsigned long times)
{
    if(scanner == NULL)
        return 0;
#ifdef BOOST_1_47
	using namespace boost::filesystem2;
#else
	using namespace boost::filesystem;
#endif
    if(!exists(KadCrawl::KadUtil::log_directory))
    {
        create_directory(KadCrawl::KadUtil::log_directory);   
    }
    for(unsigned int i=0;i<times;i++)
    {
        for(unsigned j=0;j<30;j++)
        {
            scanner->removeDuplicates();
            scanner->resetIncomingPeerCount();
	        updateNodesByBootstrapReq(2);
            kad_wait(3);
            scanner->processBuffer();
	        scanner->updateSendQueue();
	        scanner->removeDuplicates();
        }
        KadUtil::saveNodesInfoToDefaultPath(2,scanner->GetNodeList()); 
        kad_wait(30);
        scanner->resetAllToInitialState();
    }
    return 0;
}
unsigned long KadCrawleManager::updateNodeByFullQuery(unsigned int coff)
{
	if(scanner == NULL)
		return 0;
    unsigned long limit = (unsigned long)pow((double)2,(double)coff);
    /*
    CUInt128 node_id = KadUtil::kad_id;
	list<CUInt128> query2nodes;
	for(unsigned int i=0;i<limit;i++)
	{
		CUInt128 id = node_id;
		id.setPrefixBits(0,coff,i);
		query2nodes.push_back(id);
	}
    */
	list<KadNode> nodeList = scanner->GetUnRequestedNodeList();
	list<CUInt128>::iterator id_it;
    list<KadNode>::iterator it;
    //for(id_it = query2nodes.begin();id_it != query2nodes.end();id_it++)
    for(unsigned int i=0;i<limit;i++)
	{
		for(it = nodeList.begin();it != nodeList.end();it++)
		{
			KadNode& tnode = *it;
            CUInt128 id = tnode.kad_id;
            id.setPrefixBits(0,coff,i);
			scanner->sendNodeLookupReq(id,tnode,20);
		}
		boost::this_thread::sleep(boost::posix_time::milliseconds(5000)); 
        std::ostringstream stream;
        //stream<<"sub round of crawl "<<distance(query2nodes.begin(),id_it)<<" of "<<query2nodes.size()<<endl;
        stream<<"sub round of crawl "<<i<<" of "<<limit<<endl;
        KadLogger::Log(INFO_KAD_LOG,stream.str());
	}
	return 0;
}

unsigned long KadCrawleManager::updateNodesAndCleanUp(CUInt128& node_id,unsigned int base,unsigned int coff)
{
	if(scanner == NULL)
		return 0;
	
	unsigned long limit = (unsigned long)pow((double)2,(double)coff);
	list<CUInt128> query2nodes;
	for(unsigned int i=0;i<limit;i++)
	{
		CUInt128 id = node_id;
		id.setPrefixBits(base,coff,i);
		query2nodes.push_back(id);
	}

	unsigned long ipaddr=0;
	list<KadNode> nodeList = scanner->GetUnRequestedNodeList();
	list<KadNode>::iterator it;
	list<CUInt128>::iterator id_it;
    using namespace boost::posix_time;
    ptime program_start_time = second_clock::local_time();
	for(id_it = query2nodes.begin();id_it != query2nodes.end();id_it++)
	{
		for(it = nodeList.begin();it != nodeList.end();it++)
		{
			KadNode& tnode = *it;
			scanner->sendNodeLookupReq(*id_it,tnode,20);
		}
	}
    ptime program_end_time = second_clock::local_time();
    time_duration alltime_duration = program_end_time - program_start_time;
    unsigned int remaining_seconds = limit*6-alltime_duration.seconds()+1;
	kad_wait(2);  
	return 0;
}

/**
 * @brief search file related information:keyword,file sources etc.
 *
 * @Param keyword : start search with specific keyword
 */
void KadCrawleManager::searchKeywordOp(string keyword)
{
	list<KadNode> nodeList = scanner->GetNodeList();
	list<KadNode>::iterator it;
	
	CUInt128 keyword_id = KadUtil::getInt128FromString(keyword);
	for(int i=0;i<6;i++)
	{
		updateNodesAndCleanUp(keyword_id,8,2);
        scanner->processBuffer();
		scanner->removeDuplicates();
		scanner->updateSendQueue();
		scanner->removeDuplicates();
	}
		
	nodeList = scanner->GetNodeList();

	DEBUG_PRINT1("Starting to send keyword request for fileinfo\n");
	for(it = nodeList.begin();it != nodeList.end();it++)
	{
		KadNode& tnode = *it;
		scanner->sendKeywordLookupReq(keyword,tnode);
    }
	DEBUG_PRINT1("Send keyword request for fileinfo complete\n");

	kad_wait(5);
    scanner->processBuffer();
	scanner->removeDuplicates();

	nodeList = scanner->GetNodeList();
	list<KadSharedFile> fileList = scanner->GetSharedFileList();
	
	DEBUG_PRINT1("Starting to send source request for fileinfo\n");

	scanner->setSearchResultType(SEARCH_FILE);
	std::ostringstream stream;
	stream<<"Start to search file source,total size: ";
	stream<<fileList.size();
	KadLogger::Log(INFO_KAD_LOG,stream.str());
	int count=1;
	for(list<KadSharedFile>::iterator tit=fileList.begin();tit!=fileList.end();tit++)
	{
		KadSharedFile sFile= *tit;
		CUInt128 target_id = sFile.fileHash;
		scanner->setToNearerNodesFromBootNodes(target_id,20);
		for(int i=0;i<2;i++)
		{
			updateNodesAndCleanUp(target_id,8,1);
            scanner->processBuffer();
			scanner->removeDuplicates();
			scanner->updateSendQueue();
			scanner->removeDuplicates();
		}
		scanner->sendSearchFileSourceRequest(sFile);
        kad_wait(2);
		std::ostringstream stream;
		stream<<"search file source round : "<<count<<" complete";
		KadLogger::Log(INFO_KAD_LOG,stream.str());
		count++;
	}
    scanner->processBuffer();
	scanner->removeDuplicates();
	DEBUG_PRINT1("Source request for fileinfo complete\n");
	KadLogger::Log(INFO_KAD_LOG,scanner->DumpKadSharedFiles());
	DatabaseLogger logger;
	logger.init("kadFiles.sqlite");
	logger.SaveAllFileNode(scanner->GetSharedFileList());
	logger.destroy();
}

void KadCrawleManager::searchFileSharedPeers(string keyword)
{
	list<KadNode> nodeList = scanner->GetNodeList();
	list<KadNode>::iterator it;

	for(it = nodeList.begin();it != nodeList.end();it++)
	{
		KadNode& tnode = *it;

		scanner->sendKeywordTargetLookupReq(keyword,tnode);
		boost::this_thread::sleep(boost::posix_time::milliseconds(1)); 
	}

	kad_wait(5);

	scanner->updateSendQueue();

	nodeList.clear();
	nodeList = scanner->GetNodeList();

	DEBUG_PRINT1("Starting to connect with peer directly\n");

	for(it = nodeList.begin();it != nodeList.end();it++)
	{
		KadNode& tnode = *it;
		
		fileQueryEngine->Connect(tnode);
		
		boost::this_thread::sleep(boost::posix_time::milliseconds(1)); 
	}
}

void KadCrawleManager::findUnbuddyedActiveNodes(list<KadNode>& nodes)
{
	list<KadNode>::iterator it = nodes.begin();
	for(;it != nodes.end();it++)
	{
		KadNode& node = *it;
		scanner->sendFindBuddyReq(node);
	}
}

void KadCrawleManager::crawl8bitZone(CUInt128& node_id)
{
	
}

void KadCrawleManager::crawlSingleNode(unsigned int coff)
{
	singleCrawleEvent.reset();
	DEBUG_PRINT1("waiting for active peer coming \n");
	singleCrawleEvent.wait();

	if(ActiveIPs.size() == 0)
		return;
	unsigned long target = ActiveIPs[3];

	list<KadNode>::const_iterator it;
	it = std::find_if(scanner->GetNodeList().begin(),scanner->GetNodeList().end(),findKadNodeByIP(target));

	if(it == scanner->GetNodeList().end())
	{
		DEBUG_PRINT1("node not found\n");
		return;
	}
    /*
	char ipTargetStr[] = "192.168.1.126";
	unsigned long src_addr = inet_addr("192.168.1.116");
	unsigned long target_addr = inet_addr(ipTargetStr);

    
	KadNode target_node;
	unsigned long target_id_bytes[4]={
		3179235593UL,
		443396052UL,
		3215202336UL,
		1450183149UL
	};
	CUInt128 target_id;
	target_id.directAssign(target_id_bytes[0],
		target_id_bytes[1], 
		target_id_bytes[2],
		target_id_bytes[3]
	);
	target_node.kad_id = target_id;
	target_node.ipNetOrder = target_addr;
	target_node.udp_port = 41218;
	target_node.tcp_port = 58699;

	KadNode& node = target_node;
    */	
	KadNode node = *it;
	DEBUG_PRINT5("\nscan node with ip %s ,udp_port %u ,tcp_port %u  %s\n",inet_ntoa(*((in_addr*)&target)),node.udp_port,node.tcp_port,KadUtil::getCountryNameFromIP(target).c_str());

	list<CUInt128> query2nodes;
	unsigned int base = 0;
	unsigned long limit = (unsigned long)pow((double)2,(double)coff);
	for(unsigned int i=0;i<limit;i++)
	{
		CUInt128 id = node.kad_id;
		id.setPrefixBits(0,coff,i);
		query2nodes.push_back(id);
	}
	list<CUInt128>::iterator id_it;
	for(id_it = query2nodes.begin();id_it != query2nodes.end();id_it++)
	{
		scanner->sendNodeLookupReq(*id_it,node,20);
        kad_wait(6);
	}
	singleCrawleEvent.reset();
	DEBUG_PRINT1("Single node crawle complete\n");
	scanner->updateSendQueue();
}

void KadCrawleManager::setKadScanner(KadScanner* scanner)
{
	this->scanner = scanner;
}

void KadCrawleManager::setFileQueryEngine(KadFileDownloader* downloader)
{
	this->fileQueryEngine = downloader;
}

void KadCrawleManager::receiveMessageEventHandler(unsigned long ip,unsigned char*data,unsigned long len)
{
	ActiveIPs.push_back(ip);
	if(ActiveIPs.size() == 10)
		singleCrawleEvent.set();
}
