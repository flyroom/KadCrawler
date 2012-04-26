// KadCrawler.cpp : Defines the entry point for the console application.
//
#include"config.h"
#include"DatabaseLogger.h"
#include"KadUtil.h"
#include"KadScanner.h"
#include"KadClientCredits.h"
#include"FileClientSession.h"
#include"KadFileDownloader.h"
#include"KadCrawleManager.h"
#include"KadAnalyzer.h"
#ifndef WIN32
#include <termios.h>
#include <unistd.h>
#endif

using namespace boost;
using namespace KadCrawl;
#define arraysize(ar)  (sizeof(ar) / sizeof(ar[0]))
KadScanner scanner;
KadCrawleManager kadCrawler;
KadFileDownloader fileQueryEngine;
KadClientCreditsPool creditsPool;
KadAnalyzer kadAnalyzer;
#ifdef USE_BOOST_ASIO
static boost::asio::io_service io_service;
#endif
#ifndef WIN32
int _getch (void)
{
    int ch;
    struct termios oldt, newt;

    tcgetattr(STDIN_FILENO, &oldt);
    memcpy(&newt, &oldt, sizeof(newt));
    newt.c_lflag &= ~( ECHO | ICANON | ECHOE | ECHOK |
                       ECHONL | ECHOPRT | ECHOKE | ICRNL);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    return ch;
}
#endif

bool compareKadSharedFileTest(KadFileSource sourceA,KadFileSource sourceB)
{
	if(sourceA.sourceIP != sourceB.sourceIP)
		return sourceA.sourceIP<sourceB.sourceIP;
	else if( sourceA.serverTcpPort != sourceB.serverTcpPort)
		return sourceA.serverTcpPort < sourceB.serverTcpPort;
	else if(sourceA.uType != sourceB.uType)
		return sourceA.uType < sourceB.uType;
	else
		return false;
}

bool equalKadSharedFileTest(KadFileSource sourceA,KadFileSource sourceB)
{
	return sourceA.sourceIP==sourceB.sourceIP&&sourceA.serverTcpPort==sourceB.serverTcpPort&&sourceA.uType==sourceB.uType;
}
void testMD5()
{
    MD5 md5_gen;
    uint8 md5sum[16]={0};
    KadNodeStruct sKadNode;
    sKadNode.id[0] = 1493385;
    sKadNode.id[1] = 193385;
    sKadNode.id[2] = 193885;
    sKadNode.id[3] = 149385;
    sKadNode.udp_port = 3849;
    sKadNode.ipNetOrder = 4938989;
    md5_gen.Update((unsigned char*)&sKadNode,sizeof(KadNodeStruct));
    md5_gen.Final(md5sum);
    vector<char> node_key(md5sum,md5sum+sizeof(uint8)*16);
    bool passed=true;
    for(unsigned int i=0;i<10000;i++) 
    {
        MD5 md5_gen_1;
        uint8 md5sum[16]={0};
        KadNodeStruct sKadNode;
        sKadNode.id[0] = 1493385;
        sKadNode.id[1] = 193385;
        sKadNode.id[2] = 193885;
        sKadNode.id[3] = 149385;
        sKadNode.udp_port = 3849;
        sKadNode.ipNetOrder = 4938989;
        md5_gen_1.Update((unsigned char*)&sKadNode,sizeof(KadNodeStruct));
        md5_gen_1.Final(md5sum);
        vector<char> node_key_i(md5sum,md5sum+sizeof(uint8)*16);
        if(node_key_i == node_key)
        {
            passed = false;
            break;
        }
    }
    if(passed)
    {
        DEBUG_PRINT1("Passed Test\n");
    }
    else
    {
        DEBUG_PRINT1("Not Passed Test\n");
    }
}
void test()
{
    testMD5();
	string country="cota'',jfdk";
	replace(country,"'",".");  
	unsigned long testAddr = inet_addr("192.168.1.126");;
	in_addr testInAddr;;
#ifdef WIN32
	testInAddr.S_un.S_addr = testAddr;
#else
	testInAddr.s_addr = testAddr;
#endif
	DEBUG_PRINT2("ip addr: %s\n",inet_ntoa(testInAddr));
	list<KadNode> testList;
	unsigned long kad_id[4]={100,200,300,400};
	CUInt128 node_idA,node_idB,node_idC,node_idD;
	node_idA.directAssign(kad_id[0],kad_id[1],kad_id[2],kad_id[3]);
	node_idB.directAssign(kad_id[0]+20,kad_id[1]+10,kad_id[2]+10,kad_id[3]+10);
	node_idC.directAssign(kad_id[0]+30,kad_id[1]+10,kad_id[2]+10,kad_id[3]+10);
	node_idD.directAssign(kad_id[0]+40,kad_id[1]+10,kad_id[2]+10,kad_id[3]+10);

	KadNode test_nodeA1(node_idA,ntohl(12345),12,13,node_idA,8,0,true);
	KadNode test_nodeA2(node_idB,ntohl(12345),12,13,node_idB,8,0,true);
	KadNode test_nodeB(node_idC,ntohl(12345),11,13,node_idC,8,0,true);
	KadNode test_nodeC(node_idD,ntohl(12345),12,13,node_idD,8,0,true);

	testList.push_back(test_nodeA1);
	testList.push_back(test_nodeB);
	testList.push_back(test_nodeC);

	testList.sort(less<KadNode>());
	testList.erase(unique(testList.begin(),testList.end()),testList.end());

	CUInt128 node_id_n;
	node_id_n.directAssign(kad_id[0]+25,kad_id[1]+10,kad_id[2]+10,kad_id[3]+10);
	SimpleKadNode snode(node_id_n,0,0);
	testList.sort();
	list<KadNode>::iterator mid_it= lower_bound(testList.begin(),testList.end(),snode,compareByKadID);
	list<KadNode>::reverse_iterator r_mid_it(mid_it);
	if(r_mid_it != testList.rend())
	{
		KadNode& node_b = *r_mid_it;
		r_mid_it++;
	}
	KadNode& node_f = *mid_it;

	KadFileSource sA,sB,sC;
	sA.sourceIP=0;
	sA.serverTcpPort=10;
	sA.uType=1;
	sB.sourceIP=1;
	sB.serverTcpPort=11;
	sB.uType=1;
	sC.sourceIP=2;
	sC.serverTcpPort=10;
	sC.uType=2;
	vector<KadFileSource> sources;
	sources.push_back(sC);
	sources.push_back(sB);
	sources.push_back(sA);
	sources.push_back(sA);
	sort(sources.begin(),sources.end());
	sources.erase(unique(sources.begin(),sources.end()),sources.end());
	sort(sources.begin(),sources.end(),compareKadSharedFileTest);
	sources.erase(unique(sources.begin(),sources.end(),equalKadSharedFileTest),sources.end());
	/*
	DatabaseLogger dbLogger;
	dbLogger.init("kadTest.sqlite");
	dbLogger.InsertKadNode(test_nodeA1,"cota'',jfdk","CJ");
	dbLogger.destroy();
	*/
}

void init(unsigned short udp_port)
{
	char ipstr[] = "192.168.1.141";
	char ipTargetStr[] = "192.168.1.126";
	unsigned long addr = inet_addr(ipstr);
	unsigned long target_addr = inet_addr(ipTargetStr);

	unsigned long addr_search = inet_addr("61.137.191.89");
	unsigned long addr_search2 = inet_addr("218.59.144.47");
	unsigned long addr_search3 = inet_addr("58.215.57.231");
	unsigned long written_addr_search = htonl(addr_search);

	unsigned long persistent_id[4]={
		1697825625UL,
		1036740590UL,
		729181882UL,
		3757965311UL
	};

	KadNode target_node;
	unsigned long target_id_bytes[4]={
		3917962527UL,
		720664368UL,
		2357899066UL,
		661016586UL
	};
	CUInt128 target_id;
	target_id.directAssign(target_id_bytes[0],
		target_id_bytes[1],
		target_id_bytes[2],
		target_id_bytes[3]
	);
	target_node.kad_id = target_id;
	target_node.ipNetOrder = target_addr;
	target_node.udp_port = 55586;
	target_node.tcp_port = 58699;

	scanner.Init();
    kadAnalyzer.init();

    KadCrawl::KadUtil::udp_port = udp_port;
    
    DEBUG_PRINT2("%s\n",KadCrawl::KadUtil::getFullIpGeoInfoFromIP(inet_addr("8.8.4.4")).c_str());
    // set fixed kad id
	KadUtil::kad_id.directAssign(persistent_id[0],
		persistent_id[1],
		persistent_id[2],
		persistent_id[3]
	);

#ifdef USE_BOOST_ASIO
    std::ostringstream port_message;
    port_message<<"UDP Engine Use Port ";
    port_message<<udp_port;
    KadLogger::Log(INFO_KAD_LOG,port_message.str());
	AsioUDPServer* yaUdpEngine = new AsioUDPServer(io_service,udp_port);
	AsioTCPServer* tcpEngine = new AsioTCPServer(io_service,udp_port);
	yaUdpEngine->start();
	tcpEngine->start();
	scanner.setAsioServer(yaUdpEngine);
	scanner.setAsioTcpServer(tcpEngine);
#else

#endif
    fileQueryEngine.Init();
    kadCrawler.setFileQueryEngine(&fileQueryEngine);
    kadCrawler.setKadScanner(&scanner);

    //fileQueryEngine.Connect(target_node);
    /*
	string keyword="obama";
	string converted = s2utfs(keyword);

	scanner.sendKeywordLookupReq(converted,target_node);
    */	
    target_node.version=0;
    scanner.InsertNode(target_node);
    kadCrawler.updateNodesByBootstrapReq(1);
}

tuple<unsigned long,unsigned long> scanKadWithRouteQuery(CUInt128 target_id,bool retry)
{
	clock_t start,finish;
	ULONG duration;

	start = clock();
    if(scanner.GetUnRequestedNodeList().size()!=0 || retry)
    {
        kadCrawler.updateNodesAndCleanUp(target_id,8,2);
        scanner.processBuffer(); 
        kadAnalyzer.AppendNodeListSnapshot(scanner.GetNewlyDiscoveredNodeList());
        scanner.updateSendQueue();
    }
	finish = clock();
	duration = (ULONG)((finish-start)/CLOCKS_PER_SEC);
	tuple<unsigned long,unsigned long> result(duration,scanner.GetNodeList().size());
	return result;
}
vector<unsigned long> scanKadWithBootstrapQuery(unsigned int times,unsigned int version,unsigned int round)
{
    vector<unsigned long> gradual_count;
	unsigned int previous=0;
    
    for(unsigned int i=0;i<times;i++)
    {
        bool retry=false;
        if(i<5 && scanner.GetUnRequestedNodeList().size()==0)
            retry = true;

        clock_t start,finish;
        ULONG duration;
        start = clock();
        if(scanner.GetUnRequestedNodeList().size()!=0 || retry)
        {
            scanner.resetIncomingPeerCount();
            kadCrawler.updateNodesByBootstrapReq(version);
            scanner.processBuffer();
            scanner.updateSendQueue();
            kad_wait(3);	
        }
        finish = clock();
        duration = (ULONG)((finish-start)/CLOCKS_PER_SEC);
    	tuple<unsigned long,unsigned long> result(duration,scanner.GetNodeList().size());
        
        if(i == round || round==0)
        {
            list<KadNode> requestList = scanner.GetUnRequestedNodeList();
            KadLogger::Log(INFO_KAD_LOG,kadAnalyzer.AnalyzeEmuleKadNodes(requestList));
        }
        gradual_count.push_back(result.get<1>());
        if(i==0)
        {
            previous = result.get<1>();
        }
        else
        {
            if(result.get<1>()-previous<100)
            {
                //scanner.resetSendQueue();
                std::ostringstream stream;
                stream<<"Reset sending queue to live nodes ";
                stream<<result.get<1>()-previous;
                KadLogger::Log(INFO_KAD_LOG,stream.str());
            }
            previous = result.get<1>();
        }
        duration+=result.get<0>();
        std::ostringstream stream;
        stream<<"Bootstrap Request round ";
        stream<<i<<" completes in "<<result.get<0>()/60<<" minutes "<<result.get<0>()%60<<" seconds with incoming nodes size "<<result.get<1>();
        KadLogger::Log(INFO_KAD_LOG,stream.str());
    }
	return gradual_count;
}
tuple<unsigned long,unsigned long> scanKadWithSampleBootstrapQuery(unsigned int version,bool retry,unsigned int sample_rate)
{
	clock_t start,finish;
	ULONG duration;

	start = clock();

    if(scanner.GetUnRequestedNodeList().size()!=0 || retry)
    {
        scanner.resetIncomingPeerCount();
        kadCrawler.updateNodesBySampleBootstrapReq(version,sample_rate);
        scanner.processBuffer();
        scanner.updateSendQueue();
        kad_wait(3);	
    }
    finish = clock();
    duration = (ULONG)((finish-start)/CLOCKS_PER_SEC);
	tuple<unsigned long,unsigned long> result(duration,scanner.GetNodeList().size());
	return result;
}
tuple<unsigned long,unsigned long> scanKadWithMixedQuery(bool retry,unsigned long delay_between_packets_mseconds,const KadFilter& pass_filter,const KadFilter& block_filter)
{
	clock_t start,finish;
	ULONG duration;
	start = clock();
    if(scanner.GetUnRequestedNodeList().size()!=0 || retry)
    {
        scanner.resetIncomingPeerCount();
        kadCrawler.updateNodesByMixedReq(delay_between_packets_mseconds,pass_filter,block_filter);
        scanner.processBuffer();
        scanner.updateSendQueue();
        kad_wait(3);	
    }
    finish = clock();
    duration = (ULONG)((finish-start)/CLOCKS_PER_SEC);
	tuple<unsigned long,unsigned long> result(duration,scanner.GetNodeList().size());
	return result;
}
tuple<unsigned long,unsigned long> scanKadWithFullQuery(unsigned int coff,bool retry)
{
	clock_t start,finish;
	ULONG duration;

	start = clock();
    if(scanner.GetUnRequestedNodeList().size()!=0||retry)
    {
        scanner.resetIncomingPeerCount();
        kadCrawler.updateNodeByFullQuery(coff);
        scanner.processBuffer();
        scanner.updateSendQueue();

        kad_wait(3);	
    }
    finish = clock();
	duration = (ULONG)((finish-start)/CLOCKS_PER_SEC);
	tuple<unsigned long,unsigned long> result(duration,scanner.GetNodeList().size());
	return result;
}

tuple<unsigned long,unsigned long> scanKadWithFindBuddyReq()
{
	clock_t start,finish;
	ULONG duration;

	start = clock();

	scanner.removeDuplicates();
	list<KadNode> nodeList = scanner.GetUnRequestedNodeList();
	kadCrawler.findUnbuddyedActiveNodes(nodeList);
    scanner.processBuffer();
	scanner.updateSendQueue();
	scanner.removeDuplicates();

	kad_wait(3);
    finish = clock();

	duration = (ULONG)((finish-start)/CLOCKS_PER_SEC);

	tuple<unsigned long,unsigned long> result(duration,scanner.GetNodeList().size());
	return result;
}

unsigned long crawl_singleNodeHandler(unsigned long ip,unsigned char* data,unsigned long len)
{
	kadCrawler.receiveMessageEventHandler(ip,data,len);
	return 0;
}

tuple<unsigned long,unsigned long> scanSpecificRandomLiveNode(unsigned int coff)
{
	scanner.registerKadMessageHandler(KADEMLIA2_PONG,crawl_singleNodeHandler);
	boost::thread thrd1(boost::bind(&KadCrawleManager::crawlSingleNode,&kadCrawler,coff));
	kad_wait(2);
	kadCrawler.scanWithPing();
	thrd1.join();

	tuple<unsigned long,unsigned long> result(scanner.GetNodeList().size(),0);
	return result;
}

void showStatistics()
{
    string typeStatLog = kadAnalyzer.showTypesCountOfIncomingMessages();
    DEBUG_PRINT2("Type Statistics of Packets : %s\n",typeStatLog.c_str());
}
void showScanStatistics(string query_approach,unsigned int times,unsigned long duration,bool showAll)
{
    std::ostringstream stream;
    stream<<query_approach<<"  "<<times<<" times Complete In "<<duration/60<<" minutes "<<duration%60<<" seconds";
    if(showAll)
    {
        list<KadNode> nonBootstrapNodeList = scanner.GetNonBootstrapNodes();
        stream<<" with node size "<<nonBootstrapNodeList.size()<<endl;
        stream<<"In total "<<scanner.GetQuerySentCount()<<" packets sent to crawl the network"<<endl;
        double bootstrapRespondingNodeSize = scanner.GetBootstrapRespondingKadNodeList().size();
        double activePercent = bootstrapRespondingNodeSize/(double)nonBootstrapNodeList.size();
        stream<<"Active Responding Node Size: "<<bootstrapRespondingNodeSize<<" Percentage: "<<activePercent<<endl;
        stream<<"Active Unmatched Node Size: "<<scanner.GetActiveUnknowNodeSize()<<endl;
        list<SimpleKadNode> abnormal_list = scanner.getAbnormalLiveNodes();
        stream<<"Abnormal node list size: ";
        stream<<abnormal_list.size()<<endl;
        //kadAnalyzer.AnalyzeSimpleKadNodes(abnormal_list);

        stream<<endl;
        stream<<"Statistics without bootstrap nodes"<<endl;
        stream<<kadAnalyzer.AnalyzeKadActiveCount(nonBootstrapNodeList,10);
        nonBootstrapNodeList.clear();
        stream<<endl;
        stream<<"Statistics including bootstrap nodes"<<endl;
        list<KadNode> saveList = scanner.GetCrawledSnapShot();
        stream<<kadAnalyzer.AnalyzeKadActiveCount(saveList,10);
        saveList.clear();
    }
    DEBUG_PRINT2("%s\n",stream.str().c_str());
    KadLogger::Log(INFO_KAD_LOG,stream.str());
}

void Exit()
{
    //exit(0);	
    scanner.Destroy();
    KadCrawl::KadUtil::Destroy();
    io_service.stop();
}

int main(int argc, char* argv[])
{
    using namespace boost::posix_time;
	ptime program_start_time = second_clock::local_time();

	test();
	// nodes size after each scan
	list<unsigned long> gradualCount;
	bool scanned=false;
    bool quitImmediatelly=false;
	bool showGradualCount=false;
    bool processPacketImmediatelly = true;
    unsigned short udp_port=UDP_SERVER_PORT;

    unsigned long delay_seconds=0;
    unsigned long delay_between_packets_mseconds=0;
	
	boost::program_options::options_description options("KadCrawl 0.1");
	boost::program_options::variables_map vmap;

	std::vector<string> convertPair;
	std::vector<string> allEightBitZoneCrawlParams;
	std::vector<string> keywordSearchParams;
    std::vector<unsigned int> routeQueryParams;
    std::vector<unsigned int> bootstrapParams;
    std::vector<string> repetitionAnalysisParams;
    std::vector<string> nodesCompareParams;
    std::vector<unsigned int> fullRouteQueryParams;
    std::vector<string> findIPParams;
    std::vector<string> findIPDirParams;
    std::vector<string> analyzeZoneSnapShotsParams;
    std::vector<string> analyzeSessionStatisticsParams;
    std::vector<string> analyzeSessionStatisticsConcretelyParams;
    std::vector<string> analyzeSessionStatisticsQuantileParams;
    std::vector<string> analyzeIPHistoryQuantileParams;
    std::vector<string> analyzeIPHistoryQuantileByStateParams;
    std::vector<string> analyzeIPHistoryQuantileWithVersionParams;
    std::vector<string> extractSingleIPInfoFromSnapshotStream;
    std::vector<unsigned int> randBootstrapParams;
    std::vector<string> zoneNodesAnalysis;
    std::vector<unsigned long> delayParams;
    std::vector<string> countryNodesAnalysis;
    std::vector<string> versionNodesAnalysis;
    std::vector<unsigned int> mixedQueryWithVersionParams;
    std::vector<unsigned int> mixedQueryWithOutVersionParams;
   	try
	{
		options.add_options() 
			("help,h","Use -h or --help to list all arguments")
			("file,f",boost::program_options::value<vector<string> >(),"Provide input peer nodes file name")
			("lL",boost::program_options::value<string>(),"Provide input log file name")
			("port,p",boost::program_options::value<unsigned int>(),"Provide server port used by this crawler")

            // crawl
            // crawl Route
			("sQ",boost::program_options::value<vector<unsigned int> >(&routeQueryParams)->multitoken(),"Provide input times of repeated scan of RouteQuery for nodes")
			("sG",boost::program_options::value<string>()->zero_tokens(),"Provide input times of repeated scan of RouteQuery for nodes")
            // crawl all 256 kad zone 
			("sZ",boost::program_options::value<vector<string> >(&allEightBitZoneCrawlParams)->multitoken(),"Provide input times of repeated scan of RouteQuery for nodes,and final directory for output")
            // crawl kad network using native bootstrap method
			("sB",boost::program_options::value<vector<unsigned int> >(&bootstrapParams)->multitoken(),"Provide input times of repeated scan of BootstrapQuery for nodes")
            // crawl kad network using random base set
			("sR",boost::program_options::value<vector<unsigned int> >(&randBootstrapParams)->multitoken(),"Provide input times of repeated scan of BootstrapQuery through samples initial nodes set for other nodes")

            // crawl kad network using both bootstrap and route query : mixed mode
			("scan_M_generic",boost::program_options::value<unsigned int>(),"Provide input times of repeated scan of BootstrapQuery for nodes")
            // suboption of mixed mode: specify version of nodes to query
			("scan_M_version",boost::program_options::value<vector<unsigned int> >(&mixedQueryWithVersionParams)->multitoken(),"Provide input times of repeated scan of BootstrapQuery for nodes,only send packets to nodes with specified version")
            // suboption of mixed mode: query to those nodes which don't have specified version
			("scan_M_nversion",boost::program_options::value<vector<unsigned int> >(&mixedQueryWithOutVersionParams)->multitoken(),"Provide input times of repeated scan of BootstrapQuery for nodes,only send packets to nodes without specified version")
            // crawl kad network using full route query(query using all combination of first bits of id)
			("sW",boost::program_options::value<vector<unsigned int> >(&fullRouteQueryParams)->multitoken(),"Provide input times of repeated scan of FullRouteQuery for nodes")
            // crawl kad network using find buddy probe
			("sP",boost::program_options::value<unsigned int>(),"Provide input times of repeated scan of FindBuddyRequest for nodes")
            // crawl kad network for shared files information
			("sK",boost::program_options::value<vector<string> >(&keywordSearchParams)->multitoken(),"Provide the keyword to search in this network,and warmup times before search ")
            // search kad network for keyword related information using specified key
			("sT",boost::program_options::value<string>(),"Provide the keyword for related peers")
            // currently no parameters just try to crawl as many nodes from one kad node as possible
			("sS",boost::program_options::value<unsigned int>(),"Provide the crawling depth of a single peer")
            // read in particular node file and probe each one with KAD2_HelloReq
			("sH",boost::program_options::value<string>(),"Scan with HelloReq Ping")
            // read in particular node file and probe each one with KAD2_PING
			("sHP",boost::program_options::value<string>(),"Scan with Standard Ping")
            // read in particular keyword as the KAD id
			("sI",boost::program_options::value<string>(),"Scan with self id generated by md5 of specified keyword")
            // scan with helloreq as sybil 
			("sY",boost::program_options::value<unsigned int>(),"Scan with helloreq as sybil")
            // still bear bugs on memory leaks,continuiously crawl the kad network
			("dH",boost::program_options::value<unsigned long>(),"Provide the directory path name of log director")
            // read in and show detail information about particular nodes file
			("sF",boost::program_options::value<string>(),"Provide input name of the nodes file to parse and show")
            /* read in and show AS information about particular nodes file
             * 1 parameters
             *      full file path of particular node file
             */
			("sA",boost::program_options::value<string>(),"Provide input name of the nodes file to parse and show")
            // draw a native comparison between kad nodes files in specified directory statistically
			("cS",boost::program_options::value<vector<string> >(&analyzeZoneSnapShotsParams)->multitoken(),"Provide the directory to parse")
            // each node list file in the specified directory would be counted by id which is the order they'are readed
			("cZ",boost::program_options::value<string>(),"Provide the path name of target kad zone nodes file to analyze")
            // convert specified node list file to corresponding sqlite3 and csv format
			("cF",boost::program_options::value<vector<string> >(&convertPair)->multitoken(),"Provide node path of node file and sqlite3 file to convert")
            // analyze single specified kad node list file
			("aN",boost::program_options::value<string>(),"Provide the directory path name of target kad nodes file to analyze")
            // analyze kad nodes in specific zone
			("aZ",boost::program_options::value<vector<string> >(&zoneNodesAnalysis)->multitoken(),"Provide the directory path name and target 8 bit zone num of target kad nodes file to analyze")
            // analyze kad nodes in specific country
			("aC",boost::program_options::value<vector<string> >(&countryNodesAnalysis)->multitoken(),"Provide the directory path name and specific country name")
            // analyze kad nodes with specified version
			("aV",boost::program_options::value<vector<string> >(&versionNodesAnalysis)->multitoken(),"Provide the directory path name and specific version number in 0-9")
            // analyze the nodes list files in the specified directory,note only those files with specific name pattern would be readed
			("tF",boost::program_options::value<vector<string> >(&nodesCompareParams)->multitoken(),"Provide node file list directory to analyze")
            // analyze ip and id repetition statistics of kad nodes
			("tI",boost::program_options::value<vector<string> >(&repetitionAnalysisParams)->multitoken(),"Provide node file list directory to analyze")
            // analyze session statistics
			("tS",boost::program_options::value<vector<string> >(&analyzeSessionStatisticsParams)->multitoken(),"Provide node file list directory to analyze session statistics")
            // analyze session statistics concretely
            ("tD",boost::program_options::value<vector<string> >(&analyzeSessionStatisticsConcretelyParams)->multitoken(),"Provide node file list directory to analyze detailed session statistics")
            // analyze session statistics by quantile 
            ("tQ",boost::program_options::value<vector<string> >(&analyzeSessionStatisticsQuantileParams)->multitoken(),"Provide node file list directory to analyze detailed session statistics by quantile")
            // analyze ip history statistics by quantile
            ("tM-generic",boost::program_options::value<vector<string> >(&analyzeIPHistoryQuantileParams)->multitoken(),"Provide node file list directory to analyze detailed ip history statistics by quantile")
            // analyze ip history statistics of nodes with specified version by quantile
            ("tM-version",boost::program_options::value<vector<string> >(&analyzeIPHistoryQuantileWithVersionParams)->multitoken(),"Provide node file list directory to analyze detailed ip history statistics by quantile")
            // analyze ip history statistics of nodes without specified version by quantile
            ("tM-nversion",boost::program_options::value<vector<string> >(&analyzeIPHistoryQuantileWithVersionParams)->multitoken(),"Provide node file list directory to analyze detailed ip history statistics by quantile")
            // analyze live nodes ip history statistics by quantile
            ("tM-alive",boost::program_options::value<vector<string> >(&analyzeIPHistoryQuantileByStateParams)->multitoken(),"Provide node file list directory to analyze detailed live ip history statistics by quantile")
            // analyze live nodes ip history statistics by quantile
            ("tM-dead",boost::program_options::value<vector<string> >(&analyzeIPHistoryQuantileByStateParams)->multitoken(),"Provide node file list directory to analyze detailed live ip history statistics by quantile")
            // test whether the hash map is valid
            ("tT",boost::program_options::value<string>(),"provide the node file,check whether the node hash map is valid")
            // load base node list file from sqlite3 database
			("lD",boost::program_options::value<string>(),"Provide input name of sqlite3 file of nodes info")
            // log setting , set log type,not set default to file,set;1,console;2,utf8 file
			("lT",boost::program_options::value<unsigned long>(),"Provide log type")
            // load nodes ip history data
			("lH",boost::program_options::value<string>(),"Provide nodes ip history data to load")
            // check whether this ip exist in current node list
            ("eI",boost::program_options::value<vector<string> >(&findIPParams)->multitoken(),"Provide ip to check existence,if exist print all the matched items,print failure otherwise")
            // check whether this ip exist in bunch of node list in specified directory
            ("eT",boost::program_options::value<vector<string> >(&findIPDirParams)->multitoken(),"Provide directory to load huge group of nodelist,and ip to check existence,as well as its netmask to adjust query precision,if exist print all the matched items,print failure otherwise")
            // extract all the nodes info with specified ip from group of crawling snapshots
            ("eP",boost::program_options::value<vector<string> >(&extractSingleIPInfoFromSnapshotStream)->multitoken(),"extract all the info with specified ip from ")
            // whether to process the packet while receiving the packet,append 'no' to separate the process of receiving and processing
            ("instant,i","is the packet processed immediatelly or not,default yes")
            ("usehash,u","whether to use hashtable for temporary storage of nodes")
            ("delay,d",boost::program_options::value<vector<unsigned long> >(&delayParams)->multitoken(),"delay in each round of crawl")
			;
		
		boost::program_options::store(boost::program_options::parse_command_line(argc,argv,options),vmap);
        const char* config_file = "setting.conf";
        std::stringstream stream;
        stream<<"setting.conf";
		//boost::program_options::store(boost::program_options::parse_config_file(stream,options),vmap);
		boost::program_options::notify(vmap);
	}
	catch (std::exception &e)
	{
		cout<<"Error "<<e.what()<<endl;
		cout<<"Error "<<"while parsing KadCrawler Options,Exiting......"<<endl;
		exit(0);
	}
	
	if(vmap.count("help"))
	{
		cout<< options <<endl;
        return 0;
	}

	if(vmap.count("lL"))
	{
		string logfile_name = vmap["lL"].as<string>();
		KadLogger::init(INFO_KAD_LOG,logfile_name);
	}
	else
	{
		KadLogger::init();
	}
    if(vmap.count("lT"))
    {
        unsigned long log_type = vmap["lT"].as<unsigned long>();
        KadLogger::setOutputStyle((_LOG_OUTPUT)log_type);
    }
    if(vmap.count("port"))
    {
		udp_port = vmap["port"].as<unsigned int>();
    }
    if(vmap.count("instant"))
    {
        processPacketImmediatelly = false;
        scanner.setProcessImmediatelly(processPacketImmediatelly);
    }
    if(vmap.count("usehash"))
    {
        scanner.setUseHashTable(true);
    }
    if(vmap.count("delay") && (delayParams.size()==2 || delayParams.size()==1))
    {
        delay_seconds = delayParams[0];
        if(delayParams.size()==2)
        {
            delay_between_packets_mseconds = delayParams[1];
        }
    }
	init(udp_port);

	KadLogger::Log(INFO_KAD_LOG,"KadCrawler init complete\n");

    if(vmap.count("lH"))
    {
        string history_file = vmap["lH"].as<string>();    
        kadAnalyzer.loadIPHistoryStatisticsFromFile(history_file);
        quitImmediatelly = true;
    }
	if(vmap.count("file"))
	{
		vector<string> ifiles(vmap["file"].as< vector<string> >());
		vector<string>::iterator vI;
		cout << "Number of input files of nodes info: "<<ifiles.size()<<endl;
		cout << "Input file list: "<<endl;
		for(vI = ifiles.begin();vI != ifiles.end();vI++)
		{
			scanner.readKadNodesDataFile(*vI);
			cout<<"\t"<<*vI<<endl;
		}
        scanner.setAllNodesToInactive();
	}
	else
		cout << "No nodes info file specified"<<endl;

	if(vmap.count("lD"))
	{
		string db_name = vmap["loaddb"].as<string>();
		scanner.AddNodesFromSqlite(db_name);
	}

    if(vmap.count("sI"))
    {
        string keyword = vmap["sI"].as<string>();        
        KadCrawl::KadUtil::setIDByKeyword(keyword);
    }
    
	if(vmap.count("sQ")&&routeQueryParams.size()==2)
	{
		unsigned long duration=0;
		unsigned int times;
        unsigned long previous=0;
        times = routeQueryParams[0];
        unsigned char zone_index = routeQueryParams[1];
        CUInt128 target_id=KadUtil::kad_id;
        target_id.setPrefixBits(0,8,(unsigned int)(zone_index));
        scanner.removeDuplicates();
		for(unsigned int i=0;i<times;i++)
		{
            bool retry=false;
            if(i<5 && scanner.GetUnRequestedNodeList().size()==0)
                retry = true;
           	tuple<unsigned long,unsigned long> result = scanKadWithRouteQuery(target_id,retry);
			gradualCount.push_back(result.get<1>());
			duration+=result.get<0>();

			std::ostringstream stream;
            stream<<endl;
            stream<<"################## round "<<i<<"#################################"<<endl;
            
			list<KadNode> nodes = scanner.GetNodeList();
            kadAnalyzer.AnalyzeKadZoneNodesList(nodes,zone_index);
			unsigned long zone_size = count_if(nodes.begin(),nodes.end(),KadCrawl::countByIDByte(zone_index));
            
            if(i!=0)
            {
                if(zone_size-previous<100)
                {
                    std::ostringstream stream;
                    stream<<"Node Query: Reset Send Queue";
                    KadLogger::Log(INFO_KAD_LOG,stream.str());
                    //scanner.resetSendQueue();
                    //kad_wait(12);
                }
            }
            previous = zone_size;

            stream<<"Incoming node size this round: "<<scanner.getIncomingPeerCount()<<endl;
			stream<<"Direct Node Route Query round ";
			stream<<i<<" completes in "<<result.get<0>()/60<<" minutes "<<result.get<0>()%60<<" seconds with incoming nodes size "<<result.get<1>()<<" zone size "<<zone_size<<endl;
            stream<<"##########################################"<<endl;
			KadLogger::Log(INFO_KAD_LOG,stream.str());
            scanner.resetIncomingPeerCount();
		}
		scanned = true;

		std::ostringstream stream;
		stream<<"Nodes Route Query times Complete In "<<(int)duration/60<<" minutes "<<(int)duration%60<<" seconds"<<endl;
        stream<<"In total "<<scanner.GetQuerySentCount()<<" packets sent to crawl the network"<<endl;
		KadLogger::Log(INFO_KAD_LOG,stream.str());
		DEBUG_PRINT2("%s\n",stream.str().c_str());

        string analysis = kadAnalyzer.AnalyzeNodeListSnapShotsAsZoneCrawl(KadUtil::kad_id.GetByteChunk(0));
        KadLogger::Log(INFO_KAD_LOG,analysis);
        list<KadNode> nodes = scanner.GetNonBootstrapNodes();
        string total_analysis = kadAnalyzer.AnalyzeEmuleKadNodes(nodes);
        KadLogger::Log(INFO_KAD_LOG,total_analysis);
        KadUtil::saveZoneNodesInfoToDefaultPath(2,scanner.GetCrawledSnapShot(),zone_index);
	}

	if(vmap.count("sZ"))
	{
		if(allEightBitZoneCrawlParams.size() != 4)
			return -1;
		
		string seedFile = allEightBitZoneCrawlParams[0];
		unsigned int times = (unsigned int)atoi(allEightBitZoneCrawlParams[1].c_str());
		string outputDir = allEightBitZoneCrawlParams[2];
		unsigned int startIndex = (unsigned int)atoi(allEightBitZoneCrawlParams[3].c_str());
		if(startIndex > 255)
			return -1;

		scanner.readKadNodesDataFile(seedFile);

		unsigned long total_duration=0;

		for(int i=startIndex;i<256;i++)
		{
			unsigned long duration=0;
			CUInt128 target_id = KadUtil::kad_id;
			target_id.setPrefixBits(0,8,i);
			for(unsigned int j=0;j<times;j++)
			{
                bool retry=false;
                if(i<5 && scanner.GetUnRequestedNodeList().size()==0)
                     retry = true;
				tuple<unsigned long,unsigned long> result = scanKadWithRouteQuery(target_id,retry);
				gradualCount.push_back(result.get<1>());
				duration+=result.get<0>();

				list<KadNode> nodes = scanner.GetNodeList();
				unsigned long zone_size = count_if(nodes.begin(),nodes.end(),KadCrawl::countByIDByte(i));
				nodes.clear();

				std::ostringstream stream;
				stream<<"Zone Crawl Route Query round ";
				stream<<i<<" completes in "<<result.get<0>()/60<<" minutes "<<result.get<0>()%60<<" seconds with incoming nodes size"<<result.get<1>()<<" and zone size: "<<zone_size;
				KadLogger::Log(INFO_KAD_LOG,stream.str());
			}
			
			if(duration/60==0)
			{
				kad_wait(duration%60);
			}

			total_duration+=duration;
			
			std::ostringstream stream;
			stream<<outputDir;
			string filePrefix = "KadZoneCrawl";
#ifdef WIN32 
			stream<<"\\";
#else
			stream<<"/";
#endif
			stream<<filePrefix;
			stream<<i;
			stream<<".dat";
			KadUtil::saveNodesInfoToFile(stream.str().c_str(),2,scanner.GetNodeList());
			scanner.clearList();
			scanner.readKadNodesDataFile(seedFile);
		}
		
		scanned = true;
		kad_wait(60);
		
		std::ostringstream stream;
		stream<<"Zone Crawl Route Query completes in "<<total_duration/60<<" minutes "<<total_duration%60<<" seconds";
		KadLogger::Log(INFO_KAD_LOG,stream.str());
		DEBUG_PRINT2("%s\n",stream.str().c_str());
	}
    	
    /*
     * bootstrapParams 
     * first ele : node file version 
     * second ele : times to scan
     * third ele : optional round to analyze
     */
	if(vmap.count("sB")&&(bootstrapParams.size()==2||bootstrapParams.size()==3))
	{
		unsigned long duration=0;
        unsigned int version = bootstrapParams[0];
		unsigned int times = bootstrapParams[1];

        // output detailed statistics from this specific round
        unsigned int round = 500;
        if(bootstrapParams.size()==3)
            round = bootstrapParams[2];
        scanner.removeDuplicates();

        vector<unsigned long> gradual_count_scan = scanKadWithBootstrapQuery(times,version,round);
        gradualCount.insert(gradualCount.end(),gradual_count_scan.begin(),gradual_count_scan.end());
		scanned = true;
        scanner.Calibrate();
        string query_approach = "Bootstrap_query";
        showScanStatistics(query_approach,times,duration,false);
        string file_prefix = "bootNodes_bootstrap";
        KadCrawl::KadUtil::saveNodesInfoToDefaultPathWithPrefix(file_prefix,3,scanner.GetCrawledSnapShot());
	}
    /*
     * bootstrapParams 
     * first ele : node file version 
     * second ele : times to scan
     * third ele : optional round to analyze
     */
	if(vmap.count("sR")&&(randBootstrapParams.size()==3))
	{
		unsigned long duration=0;
        unsigned int version = randBootstrapParams[0];
		unsigned int times = randBootstrapParams[1];
        unsigned int sample_percent = randBootstrapParams[2];
				
		int previous=0;
        scanner.removeDuplicates();
		for(unsigned int i=0;i<times;i++)
		{
            bool retry=false;
            if(i<5 && scanner.GetUnRequestedNodeList().size()==0)
                retry = true;
			tuple<unsigned long,unsigned long> result = scanKadWithSampleBootstrapQuery(version,retry,sample_percent);
            
			gradualCount.push_back(result.get<1>());
			if(i==0)
			{
				previous = result.get<1>();
			}
			else
			{
				if(result.get<1>()-previous<100)
				{
					//scanner.resetSendQueue();
                    std::ostringstream stream;
                    stream<<"Reset sending queue to live nodes ";
                    stream<<result.get<1>()-previous;
                    KadLogger::Log(INFO_KAD_LOG,stream.str());
				}
                previous = result.get<1>();
			}
			duration+=result.get<0>();

			std::ostringstream stream;
			stream<<"Bootstrap Sample Request round ";
			stream<<i<<" completes in "<<result.get<0>()/60<<" minutes "<<result.get<0>()%60<<" seconds with incoming nodes size "<<result.get<1>();
			KadLogger::Log(INFO_KAD_LOG,stream.str());
		}
		scanned = true;
        scanner.Calibrate();
        string query_approach = "Bootstrap_sampled_query";
        showScanStatistics(query_approach,times,duration,false);
        string file_prefix = "bootNodes_bootstrap";
        KadCrawl::KadUtil::saveNodesInfoToDefaultPathWithPrefix(file_prefix,3,scanner.GetCrawledSnapShot());
	}

    KadFilter sM_pass_filter;
    KadFilter sM_block_filter;
    unsigned int sM_times=0;
    bool sM_scan=false;
    if(vmap.count("scan_M_generic"))
	{
		sM_times = vmap["scan_M_generic"].as<unsigned int>();
        sM_scan = true;
	}
    if(vmap.count("scan_M_version") && mixedQueryWithVersionParams.size()==2)
    {
        sM_times = mixedQueryWithVersionParams[0];
        unsigned int version = mixedQueryWithVersionParams[1];
        sM_pass_filter.check_flag=true;
        sM_pass_filter.check_version=true;
        sM_pass_filter.node.version=(uint8)version;
        sM_scan = true;
	}
    if(vmap.count("scan_M_nversion") && mixedQueryWithOutVersionParams.size()==2)
    {
        sM_times = mixedQueryWithOutVersionParams[0];
        unsigned int version = mixedQueryWithOutVersionParams[1];
        sM_block_filter.check_flag=true;
        sM_block_filter.check_version=true;
        sM_block_filter.node.version=(uint8)version;
        sM_scan = true;
	}
    if(sM_scan)
	{
        int previous=0;
        unsigned long duration=0;
        scanner.removeDuplicates();
        for(unsigned int i=0;i<sM_times;i++)
        {
            bool retry=false;
            if(i<5 && scanner.GetUnRequestedNodeList().size()==0)
                retry = true;
            tuple<unsigned long,unsigned long> result = scanKadWithMixedQuery(retry,delay_between_packets_mseconds,sM_pass_filter,sM_block_filter);
            gradualCount.push_back(result.get<1>());
            if(i==0)
            {
                previous = result.get<1>();
            }
            else
            {
                if(result.get<1>()-previous<100)
                {
                    //scanner.resetSendQueue();
                    std::ostringstream stream;
                    stream<<"Reset sending queue to live nodes ";
                    stream<<result.get<1>()-previous;
                    KadLogger::Log(INFO_KAD_LOG,stream.str());
                }
                previous = result.get<1>();
            }
            duration+=result.get<0>();

            std::ostringstream stream;
            stream<<"Mixed Crawl Request round ";
            stream<<i<<" completes in "<<result.get<0>()/60<<" minutes "<<result.get<0>()%60<<" seconds with incoming nodes size "<<result.get<1>();
            KadLogger::Log(INFO_KAD_LOG,stream.str());
            kad_wait(delay_seconds);
        }
        scanned = true;
        scanner.Calibrate();
        string query_approach = "Nodes Query Mixed";
        showScanStatistics(query_approach,sM_times,duration,false);
        string file_prefix = "bootNodes_mixed";
        KadCrawl::KadUtil::saveNodesInfoToDefaultPathWithPrefix(file_prefix,3,scanner.GetCrawledSnapShot());
	}
    if(vmap.count("sW"))
	{
		unsigned long duration=0;
       	unsigned int times = fullRouteQueryParams[0];
        unsigned int coff = fullRouteQueryParams[1];
				
        scanner.removeDuplicates();
		int previous=0;
		for(unsigned int i=0;i<times;i++)
		{
            bool retry=false;
            if(i<5 && scanner.GetUnRequestedNodeList().size()==0)
                retry = true;
			tuple<unsigned long,unsigned long> result = scanKadWithFullQuery(coff,retry);
			gradualCount.push_back(result.get<1>());
			if(i==0)
			{
				previous = result.get<1>();
			}
			else
			{
				if(result.get<1>()-previous<100)
				{
					//scanner.resetSendQueue();
                    std::ostringstream stream;
                    stream<<"Reset sending queue to live nodes ";
                    stream<<result.get<1>()-previous;
                    KadLogger::Log(INFO_KAD_LOG,stream.str());
				}
                previous = result.get<1>();
			}
			duration+=result.get<0>();
			std::ostringstream stream;
			stream<<"FullRouteQuery Request round ";
			stream<<i<<" completes in "<<result.get<0>()/60<<" minutes "<<result.get<0>()%60<<" seconds with incoming nodes size "<<result.get<1>();
			KadLogger::Log(INFO_KAD_LOG,stream.str());

		}
		scanned = true;
        scanner.Calibrate();
        string query_approach = "Nodes Full RouteQuery";
        showScanStatistics(query_approach,times,duration,false);
        std::ostringstream nameStream;
        nameStream<<"fullRouteQueryNodes_";
        nameStream<<getCurrentTimeString();
        nameStream<<".dat";
        KadUtil::saveNodesInfoToFile(nameStream.str(),2,scanner.GetNodeList());
	}
	if(vmap.count("sP"))
	{	
		scanKadWithFindBuddyReq();
        scanned = true;
	}
	if(vmap.count("sF"))
	{
		string file_name = vmap["sF"].as<string>();
		scanner.readKadNodesDataFile(file_name);
		DEBUG_PRINT2("%s",scanner.DumpNodesInfo().c_str());
	}
    if(vmap.count("sA"))
    {
       	string file_name = vmap["sA"].as<string>();
        list<KadNode> nodeList;
        KadUtil::readKadNodesDataToList(file_name,nodeList);
        string as_info = KadUtil::DumpNodesIPAsInfo(nodeList);
		DEBUG_PRINT2("%s",as_info.c_str());
        KadLogger::Log(INFO_KAD_LOG,as_info);
    }
	if(vmap.count("sK"))
	{
		if(keywordSearchParams.size() != 2)
			return -1;
		string keyword = keywordSearchParams[0];
		string times_s = keywordSearchParams[1];
		unsigned int times = atoi(times_s.c_str());

		kadCrawler.searchKeywordOp(s2utfs(keyword));
        scanned = true;
	}
	if(vmap.count("sT"))
	{
		string keyword = vmap["sT"].as<string>();
		kadCrawler.searchFileSharedPeers(s2utfs(keyword));
        scanned = true;
	}

	if(vmap.count("sS"))
	{
		unsigned int coff = vmap["sS"].as<unsigned int>();
		scanSpecificRandomLiveNode(coff);
		showGradualCount = true;
		DEBUG_PRINT1("\nSpecific Node Query Complete\n");
        scanned = true;
	}
	if(vmap.count("cS"))
	{
        /*
		string seedDirectory = vmap["cS"].as<string>();
		kadAnalyzer.AnalyzeEmuleKadNodeSessionLogInDir(seedDirectory);
        */
        string dir = analyzeZoneSnapShotsParams[0];
        unsigned long read_limit = atol(analyzeZoneSnapShotsParams[1].c_str());
        unsigned int time_limit = atoi(analyzeZoneSnapShotsParams[2].c_str());
        vector<string> nodeFileListToAnalyze = KadCrawl::KadUtil::getFileListOfDirectoryTimeLimited(dir,"^zoneNodes.*dat",read_limit,time_limit);
        std::ostringstream stream;
        stream<<nodeFileListToAnalyze.size()<<" files found"<<endl;
        kadAnalyzer.AnalyzeEmuleKadNodeSessionLogInDir(nodeFileListToAnalyze);
        DEBUG_PRINT2("%s\n",stream.str().c_str());
        DEBUG_PRINT1("\nParse session directory complete\n");
        quitImmediatelly = true;
	}
	if(vmap.count("cZ"))
	{
		string zoneDirectory = vmap["cZ"].as<string>();
		kadAnalyzer.AnalyzeEmuleKadZoneDir(zoneDirectory);
        quitImmediatelly = true;
	}
	if(vmap.count("cF"))
	{
		if(convertPair.size() != 2)
			return -1;
		string nodePath = convertPair[0];
		string sqlitePath = convertPair[1];
        string csvPath = convertPair[1];
        csvPath.append(".csv");
        sqlitePath.append(".sqlite");
		//KadUtil::fromNodeFileToSqlite(nodePath,sqlitePath);
        KadUtil::fromNodeFileToCsv(nodePath,csvPath);
        DEBUG_PRINT1("Conversion Complete\n");
        quitImmediatelly = true;
	}
	if(vmap.count("sH"))
	{
		kadCrawler.scanWithHelloReq();
        kad_wait(30);
        scanner.processBuffer();
        std::ostringstream stream;
        stream<<"Live Nodes Size: "<<scanner.GetTempLiveNodes().size()<<endl;
        stream<<"Total Nodes Size: "<<scanner.GetNodeList().size();
        DEBUG_PRINT2("%s\n",stream.str().c_str());
        KadLogger::Log(INFO_KAD_LOG,stream.str());
        std::ostringstream nameStream;
        nameStream<<KadCrawl::KadUtil::log_directory;
#ifdef WIN32
        nameStream<<"\\";
#else
        nameStream<<"/";
#endif
        nameStream<<"liveNodes_hellping_";
        nameStream<<getCurrentTimeString();
        nameStream<<".dat";
        KadCrawl::KadUtil::saveNodesInfoToFile(nameStream.str(),2,scanner.GetTempLiveNodes());
        scanned = true;
	}
	if(vmap.count("sHP"))
	{
		kadCrawler.scanWithPing();
        kad_wait(10);
        scanner.processBuffer();
        list<KadNode> pingAliveNodes = scanner.processPingAliveNodes();
        kadAnalyzer.AnalyzeEmuleKadNodes(pingAliveNodes);
        std::ostringstream stream;
        stream<<"Live Nodes Size: "<<scanner.GetTempLiveNodes().size()<<endl;
        stream<<"Total Nodes Size: "<<scanner.GetNodeList().size();
        DEBUG_PRINT2("%s\n",stream.str().c_str());
        KadLogger::Log(INFO_KAD_LOG,stream.str());
        std::ostringstream nameStream;
        nameStream<<KadCrawl::KadUtil::log_directory;
#ifdef WIN32
        nameStream<<"\\";
#else
        nameStream<<"/";
#endif
        nameStream<<"liveNodes_ping_";
        nameStream<<getCurrentTimeString();
        nameStream<<".dat";
        KadCrawl::KadUtil::saveNodesInfoToFile(nameStream.str(),2,scanner.GetTempLiveNodes());
        scanned = true;
	}
	if(vmap.count("sY"))
	{
		unsigned int zone_prefix = vmap["sY"].as<unsigned int>();
        unsigned int times=1;
        while(true)
        {
            DEBUG_PRINT2("%u: begin to inject this sybil node\n",times);
            kadCrawler.scanWithHelloReqUseSybils(zone_prefix);
            kad_wait(30);
            scanner.processBuffer();
            showStatistics();
            times++;
        }
        scanned = true;
	}
	if(vmap.count("aN"))
	{
		string nodeFile = vmap["aN"].as<string>();
		kadAnalyzer.AnalyzeEmuleKadNodesFile(nodeFile);
        quitImmediatelly = true;
    }
    if(vmap.count("aZ") && zoneNodesAnalysis.size() == 2)
    {
        string nodeFile = zoneNodesAnalysis[0];
        string zone_index_str = zoneNodesAnalysis[1];
        unsigned int zone_index = atoi(zone_index_str.c_str());
        kadAnalyzer.AnalyzeEmuleKadNodesFileInSpecifiedZone(nodeFile,zone_index);
        quitImmediatelly=true;
    }
    if(vmap.count("aC") && countryNodesAnalysis.size() == 2)
    {
        string nodeFile = countryNodesAnalysis[0];
        string country_str = countryNodesAnalysis[1];
        kadAnalyzer.AnalyzeEmuleKadNodesFileInSpecifiedCountry(nodeFile,country_str);
        quitImmediatelly=true;
    }
    if(vmap.count("aV") && versionNodesAnalysis.size() == 2)
    {
        string nodeFile = versionNodesAnalysis[0];
        string version_str = versionNodesAnalysis[1];
        unsigned int version = atoi(version_str.c_str());
        if(version > 9)
        {
            DEBUG_PRINT1("invalid kad version specified\n");
            return -1;
        }
        kadAnalyzer.AnalyzeEmuleKadNodesFileWithSpecifiedVersion(nodeFile,version);
        quitImmediatelly=true;
    }
    if(vmap.count("tF") && nodesCompareParams.size()==3)
    {
       string dir = nodesCompareParams[0];
       string count_limit_str=nodesCompareParams[1];
       string time_limit_str=nodesCompareParams[2];
       unsigned int count_limit = (unsigned int)atoi(count_limit_str.c_str());
       unsigned int time_limit_minutes = (unsigned int)atoi(time_limit_str.c_str());
       vector<string> nodeFileListToAnalyze = KadCrawl::KadUtil::getFileListOfDirectoryTimeLimited(dir,"^bootNodes.*dat",count_limit,time_limit_minutes);
       std::ostringstream filesstream; 
       filesstream<<"find nodes by ip in directory"<<endl;
       filesstream<<nodeFileListToAnalyze.size()<<" files found"<<endl;
       DEBUG_PRINT2("%s\n",filesstream.str().c_str());

       vector<list<KadNode> > nodeListVector;        
       for(unsigned int i=0;i<nodeFileListToAnalyze.size();i++)
       {
           list<KadNode> localList;
           string filePath = nodeFileListToAnalyze[i];
           KadUtil::readKadNodesDataToList(filePath,localList);
           nodeListVector.push_back(localList);
       }
       string result = kadAnalyzer.AnalyzeCollectionOfKadNodeList(nodeListVector);
       KadLogger::Log(INFO_KAD_LOG,result);
       std::ostringstream stream;
       stream<<"Analysis of node file list complete";
       DEBUG_PRINT2("%s\n",stream.str().c_str());
       DEBUG_PRINT2("%s",result.c_str());
       quitImmediatelly = true;
    }
    if(vmap.count("tI") && repetitionAnalysisParams.size()==3)
    {
        string dir = repetitionAnalysisParams[0];
        unsigned long read_limit = atol(repetitionAnalysisParams[1].c_str());
        unsigned int time_limit = atoi(repetitionAnalysisParams[2].c_str());
        vector<string> nodeFileListToAnalyze = KadCrawl::KadUtil::getFileListOfDirectoryTimeLimited(dir,"^bootNodes.*dat",read_limit,time_limit);
        std::ostringstream stream;
        stream<<nodeFileListToAnalyze.size()<<" files found"<<endl;
        DEBUG_PRINT2("%s\n",stream.str().c_str());

        string result = kadAnalyzer.AnalyzeIPRepititionOfKadNodeListByPathList(nodeFileListToAnalyze);
        DEBUG_PRINT2("%s\n",result.c_str());
        string resultIP = kadAnalyzer.AnalyzeRepititionOfKadNodeListByPathList(nodeFileListToAnalyze);
        DEBUG_PRINT2("%s\n",resultIP.c_str());
        KadLogger::Log(INFO_KAD_LOG,resultIP);
        KadLogger::Log(INFO_KAD_LOG,result);
        quitImmediatelly = true;
    }
    if(vmap.count("tS") && analyzeSessionStatisticsParams.size()==3)
    {
		string nodesDir = analyzeSessionStatisticsParams[0];
        string maximum_files_param = analyzeSessionStatisticsParams[1];
        string country_code = analyzeSessionStatisticsParams[2];
        unsigned long maximum_files = atol(maximum_files_param.c_str());
        if(country_code == "ALL")
        {
            const char* country_code_chararray[] = {"CN","IT","ES","FR","TW","BR","US","IL","DE","AR","PL","HK","CA"};
            vector<string> country_code_array(country_code_chararray, country_code_chararray + arraysize(country_code_chararray));
            for(unsigned int i=0;i<country_code_array.size();i++)
            {
                string country_code_string = country_code_array[i];
                CompactSessionNodeMap map = kadAnalyzer.getLiveSessionStatisticsCompactWithOptionalCountryCode(nodesDir,"^bootNodes.*dat",maximum_files,-1,country_code_string);
                string result = kadAnalyzer.dumpCompactSessionStatistics(map);
                KadLogger::Log(INFO_KAD_LOG,result);
                std::ostringstream stream;
                stream<<"analysis for country&region "<<country_code_string<<result<<endl;
                DEBUG_PRINT2("%s",stream.str().c_str());
            }
        }
        else
        {
            CompactSessionNodeMap map = kadAnalyzer.getLiveSessionStatisticsCompactWithOptionalCountryCode(nodesDir,"^bootNodes.*dat",maximum_files,-1,country_code);
            string result = kadAnalyzer.dumpCompactSessionStatistics(map);
            KadLogger::Log(INFO_KAD_LOG,result);
            DEBUG_PRINT3("analysis for country&region %s\n%s\n",country_code.c_str(),result.c_str());
        }
        quitImmediatelly = true;
    }
    if(vmap.count("tD") && analyzeSessionStatisticsConcretelyParams.size()==2)
    {
		string nodesDir = analyzeSessionStatisticsConcretelyParams[0];
        string maximum_files_param = analyzeSessionStatisticsConcretelyParams[1];
        unsigned long maximum_files = atol(maximum_files_param.c_str());

        SessionNodeMap map = kadAnalyzer.getLiveSessionStatistics(nodesDir,"^bootNodes.*dat",maximum_files,-1);
        string result = kadAnalyzer.dumpSessionStatistics(map,maximum_files);
        KadLogger::Log(INFO_KAD_LOG,result);
        quitImmediatelly = true;
    }
    if(vmap.count("tQ") && analyzeSessionStatisticsQuantileParams.size()==4)
    {
		string nodesDir = analyzeSessionStatisticsQuantileParams[0];
        string maximum_files_param = analyzeSessionStatisticsQuantileParams[3];
        string quantile_begin_str =  analyzeSessionStatisticsQuantileParams[1];
        string quantile_end_str =  analyzeSessionStatisticsQuantileParams[2];
        unsigned long maximum_files = atol(maximum_files_param.c_str());
        unsigned long quantile_begin = atol(quantile_begin_str.c_str()); 
        unsigned long quantile_end = atol(quantile_end_str.c_str()); 

        string boot_file_filter = "^bootNodes.*dat";
        vector<boost::tuple<string,time_t> > files = KadCrawl::KadUtil::getFileListOfDirectoryByTimeQuantile(nodesDir,boot_file_filter,quantile_begin,quantile_end,maximum_files);
        SessionNodeMap map = kadAnalyzer.getLiveSessionStatisticsGeneric(files);
        string result = kadAnalyzer.dumpSessionStatistics(map,maximum_files);
        KadLogger::Log(INFO_KAD_LOG,result);
        quitImmediatelly = true;
    }

    bool tM = false;
    string tM_nodesDir;
    unsigned long tM_prefix_begin;
    unsigned long tM_prefix_end;
    unsigned long tM_maximum_files;
    unsigned long tM_quantile_begin;
    unsigned long tM_quantile_end;
    unsigned long tM_version;
    KadFilter tM_pass_filter;
    KadFilter tM_block_filter;
    
    if(vmap.count("tM-generic") && analyzeIPHistoryQuantileParams.size() == 6)
    {
		tM_nodesDir = analyzeIPHistoryQuantileParams[0];
        string prefix_begin_str = analyzeIPHistoryQuantileParams[1];
        string prefix_end_str = analyzeIPHistoryQuantileParams[2];
        string quantile_begin_str =  analyzeIPHistoryQuantileParams[3];
        string quantile_end_str =  analyzeIPHistoryQuantileParams[4];
        string maximum_files_param = analyzeIPHistoryQuantileParams[5];

        tM_prefix_begin = atol(prefix_begin_str.c_str());
        tM_prefix_end = atol(prefix_end_str.c_str());
        tM_maximum_files = atol(maximum_files_param.c_str());
        tM_quantile_begin = atol(quantile_begin_str.c_str()); 
        tM_quantile_end = atol(quantile_end_str.c_str()); 
        tM = true;
    }
    if(vmap.count("tM-version") && analyzeIPHistoryQuantileWithVersionParams.size() == 7)
    {
		tM_nodesDir = analyzeIPHistoryQuantileWithVersionParams[0];
        string prefix_begin_str = analyzeIPHistoryQuantileWithVersionParams[1];
        string prefix_end_str = analyzeIPHistoryQuantileWithVersionParams[2];
        string quantile_begin_str =  analyzeIPHistoryQuantileWithVersionParams[3];
        string quantile_end_str =  analyzeIPHistoryQuantileWithVersionParams[4];
        string maximum_files_param = analyzeIPHistoryQuantileWithVersionParams[5];
        string version_param = analyzeIPHistoryQuantileWithVersionParams[6];

        tM_prefix_begin = atol(prefix_begin_str.c_str());
        tM_prefix_end = atol(prefix_end_str.c_str());
        tM_maximum_files = atol(maximum_files_param.c_str());
        tM_quantile_begin = atol(quantile_begin_str.c_str()); 
        tM_quantile_end = atol(quantile_end_str.c_str()); 
        tM_version = atol(version_param.c_str());
        tM_pass_filter.check_flag = true;
        tM_pass_filter.check_version = true;
        tM_pass_filter.node.version = tM_version;
        tM = true;
    }
    if(vmap.count("tM-nversion") && analyzeIPHistoryQuantileWithVersionParams.size() == 7)
    {
		tM_nodesDir = analyzeIPHistoryQuantileWithVersionParams[0];
        string prefix_begin_str = analyzeIPHistoryQuantileWithVersionParams[1];
        string prefix_end_str = analyzeIPHistoryQuantileWithVersionParams[2];
        string quantile_begin_str =  analyzeIPHistoryQuantileWithVersionParams[3];
        string quantile_end_str =  analyzeIPHistoryQuantileWithVersionParams[4];
        string maximum_files_param = analyzeIPHistoryQuantileWithVersionParams[5];
        string version_param = analyzeIPHistoryQuantileWithVersionParams[6];

        tM_prefix_begin = atol(prefix_begin_str.c_str());
        tM_prefix_end = atol(prefix_end_str.c_str());
        tM_maximum_files = atol(maximum_files_param.c_str());
        tM_quantile_begin = atol(quantile_begin_str.c_str()); 
        tM_quantile_end = atol(quantile_end_str.c_str()); 
        tM_version = atol(version_param.c_str());
        tM_block_filter.check_flag = true;
        tM_block_filter.check_version = true;
        tM_block_filter.node.version = tM_version;
        tM = true;
    }
    if(vmap.count("tM-alive") && analyzeIPHistoryQuantileByStateParams.size() == 6)
    {
		tM_nodesDir = analyzeIPHistoryQuantileByStateParams[0];
        string prefix_begin_str = analyzeIPHistoryQuantileByStateParams[1];
        string prefix_end_str = analyzeIPHistoryQuantileByStateParams[2];
        string quantile_begin_str =  analyzeIPHistoryQuantileByStateParams[3];
        string quantile_end_str =  analyzeIPHistoryQuantileByStateParams[4];
        string maximum_files_param = analyzeIPHistoryQuantileByStateParams[5];

        tM_prefix_begin = atol(prefix_begin_str.c_str());
        tM_prefix_end = atol(prefix_end_str.c_str());
        tM_maximum_files = atol(maximum_files_param.c_str());
        tM_quantile_begin = atol(quantile_begin_str.c_str()); 
        tM_quantile_end = atol(quantile_end_str.c_str()); 

        tM_pass_filter.check_flag=true;
        tM_pass_filter.check_kad_state=true;
        tM_pass_filter.node.state=KAD_ALIVE;
        tM = true;
    }
    if(vmap.count("tM-dead") && analyzeIPHistoryQuantileByStateParams.size() == 6)
    {
		tM_nodesDir = analyzeIPHistoryQuantileByStateParams[0];
        string prefix_begin_str = analyzeIPHistoryQuantileByStateParams[1];
        string prefix_end_str = analyzeIPHistoryQuantileByStateParams[2];
        string quantile_begin_str =  analyzeIPHistoryQuantileByStateParams[3];
        string quantile_end_str =  analyzeIPHistoryQuantileByStateParams[4];
        string maximum_files_param = analyzeIPHistoryQuantileByStateParams[5];

        tM_prefix_begin = atol(prefix_begin_str.c_str());
        tM_prefix_end = atol(prefix_end_str.c_str());
        tM_maximum_files = atol(maximum_files_param.c_str());
        tM_quantile_begin = atol(quantile_begin_str.c_str()); 
        tM_quantile_end = atol(quantile_end_str.c_str()); 

        tM_pass_filter.check_flag=true;
        tM_pass_filter.check_kad_state=true;
        tM_pass_filter.node.state=KAD_DEAD;
        tM = true;
    }
    if(tM)
    {
        string boot_file_filter = "^bootNodes.*dat";
        vector<boost::tuple<string,time_t> > files = KadCrawl::KadUtil::getFileListOfDirectoryByTimeQuantile(tM_nodesDir,boot_file_filter,tM_quantile_begin,tM_quantile_end,tM_maximum_files);
        kadAnalyzer.getIPHistoryStatisticsGeneric(files,tM_prefix_begin,tM_prefix_end,tM_pass_filter,tM_block_filter);
        quitImmediatelly = true;
    }
    if(vmap.count("tT"))
    {
        string nodesDir = vmap["tT"].as<string>();
        scanner.readKadNodesDataFile(nodesDir);
        scanner.setUseHashTable(true);
        const list<KadNode>& nodeList = scanner.GetNodeList();
        for(list<KadNode>::const_iterator it=nodeList.begin();it!=nodeList.end();it++)
        {
            const KadNode& node = *it;
            scanner.putNodeToTempList(node);
        }
        std::ostringstream stream;
        stream<<"Size of NodeList in File : "<<nodeList.size()<<endl;
        stream<<"Size of Nodes after inserting to map : "<<scanner.GetNodesMap().size()<<endl;
        list<KadNode> nodeList_temp = nodeList;
        KadCrawl::KadUtil::removeDuplicates(nodeList_temp);
        stream<<"Size of Nodes after remove duplicates : "<<nodeList_temp.size()<<endl;
        DEBUG_PRINT2("%s\n",stream.str().c_str());
        KadLogger::Log(INFO_KAD_LOG,stream.str());
        quitImmediatelly = true;
    }
    if(vmap.count("dH"))
    {
       string daily_log_directory = "daily_log";
       unsigned long times = vmap["dH"].as<unsigned long>();
       kadCrawler.updateNodesByBootstrapReqPeriodically(times);
    }
    if(vmap.count("eI") && findIPParams.size()==2)
    {
        string ip_str = findIPParams[0];
        unsigned int netmask_order = atoi(findIPParams[1].c_str());
        list<KadNode> nodes_found = kadAnalyzer.findNodesByIP(scanner.GetNodeList(),ip_str,netmask_order);
        if(nodes_found.size() != 0)
        {
            std::ostringstream stream;
            stream<<"This ip has been found by our crawler: ";
            stream<<ip_str<<"   with following matches (netmask: "<<netmask_order<<")"<<endl;
            stream<<KadUtil::DumpNodesInfo(nodes_found);
            KadLogger::Log(INFO_KAD_LOG,stream.str());        
            DEBUG_PRINT2("%s\n",stream.str().c_str());
        }
        else
        {
            std::ostringstream stream;
            stream<<"This ip has not been found yet ";
            stream<<ip_str;
            KadLogger::Log(INFO_KAD_LOG,stream.str());        
            DEBUG_PRINT2("%s\n",stream.str().c_str());
        }
        DEBUG_PRINT1("Find ip in node set complete\n");
        quitImmediatelly = true;
    }
    if(vmap.count("eT") && findIPDirParams.size()==4)
    {
        string nodes_dir = findIPDirParams[0];
        string ip_str = findIPDirParams[1];
        unsigned int netmask_order = atoi(findIPDirParams[2].c_str());
        unsigned int elapsed_minutes = atoi(findIPDirParams[3].c_str());
        list<KadNode> nodes = kadAnalyzer.findNodesByIPInDirectory(nodes_dir,"(^bootNodes.*dat|^zoneNodes.*dat)",ip_str,netmask_order,elapsed_minutes);
        DEBUG_PRINT2("Total occurences of this ip segment %u\n",(unsigned int)nodes.size());
        KadCrawl::KadUtil::removeDuplicates(nodes);
        DEBUG_PRINT2("Total distinct occurences of this ip segment %u\n",(unsigned int)nodes.size());
        KadLogger::Log(INFO_KAD_LOG,KadCrawl::KadUtil::DumpNodesInfo(nodes));
        quitImmediatelly = true;
    }
    if(vmap.count("eP") && extractSingleIPInfoFromSnapshotStream.size()==6)
    {
        string nodes_dir = extractSingleIPInfoFromSnapshotStream[0];
        string ip_str = extractSingleIPInfoFromSnapshotStream[1];
        unsigned int netmask_order = atoi(extractSingleIPInfoFromSnapshotStream[2].c_str());
        unsigned int quantile_begin = atoi(extractSingleIPInfoFromSnapshotStream[3].c_str());
        unsigned int quantile_end = atoi(extractSingleIPInfoFromSnapshotStream[4].c_str());
        unsigned int maximum_files = atoi(extractSingleIPInfoFromSnapshotStream[5].c_str());
        list<KadNode> nodes = kadAnalyzer.findNodesByIPInDirectoryByQuantile(nodes_dir,"(^bootNodes.*dat|^zoneNodes.*dat)",ip_str,netmask_order,quantile_begin,quantile_end,maximum_files);
        DEBUG_PRINT2("Total occurences of this ip segment %u\n",(unsigned int)nodes.size());
        KadCrawl::KadUtil::removeDuplicates(nodes);
        DEBUG_PRINT2("Total distinct occurences of this ip segment %u\n",(unsigned int)nodes.size());
        KadLogger::Log(INFO_KAD_LOG,KadCrawl::KadUtil::DumpNodesInfo(nodes));
        quitImmediatelly = true;
    }
	char command;
	if(scanned || quitImmediatelly)
		command='q';
	else
		command = _getch();
	while(true)
	{
        if(command == 'p')
        {
            scanner.processBuffer();
        }
		if(command == 's')
		{
			scanner.removeDuplicates();
			//DEBUG_PRINT1(scanner.DumpRoutingZoneInfo().c_str());
			
#ifdef USE_BOOST_ASIO
		DEBUG_PRINT2("\nresponded nodes size: %lu\n",scanner.getUdpEngine()->count);
#endif
			string gradualCountMsg;

			if(showGradualCount)
			{
				gradualCountMsg="single crawl nodes size step by step:";
				vector<unsigned long>::iterator count_a = scanner.gradual_count.begin();
				while(count_a != scanner.gradual_count.end())
				{
					std::ostringstream stream;
					stream<<*count_a;
					gradualCountMsg.append(stream.str());
					gradualCountMsg.append(" ");
					count_a++;
				}

				gradualCountMsg.append("\n");
				DEBUG_PRINT2("%s",gradualCountMsg.c_str());
			}
		
			DEBUG_PRINT2("%s",scanner.DumpNodesIPGeoInfo().c_str());
			DEBUG_PRINT2("%s",KadUtil::showDuplicateCountDuringSearch().c_str());
			DEBUG_PRINT2("\nNewly Discovered node count:  %u\n",(unsigned int)scanner.GetNonBootstrapNodes().size());
			DEBUG_PRINT2("Bootstrap node count:   %u\n",(unsigned int)(scanner.GetNodeList().size()-scanner.GetNonBootstrapNodes().size()));

            // show live node's percentage of all nodes
			list<KadNode> nodeList = scanner.GetNodeList();
			list<SimpleKadNode> s_nodeList = scanner.GetTempLiveNodes();
			DEBUG_PRINT2("%s",kadAnalyzer.AnalyzeLiveKadNodes(nodeList,s_nodeList).c_str());
            // show the statistics about the active nodes
            DEBUG_PRINT1("\nActive Node statistics\n");
            list<KadNode> activeList = scanner.GetActiveKadNode();
            DEBUG_PRINT2("%s",kadAnalyzer.AnalyzeEmuleKadNodes(activeList).c_str());
            DEBUG_PRINT1("\nActive RouteQuery Node Statistics\n");
            list<KadNode> activeRouteQueryNodeList = scanner.GetActiveRouteQueryNodeList();
            DEBUG_PRINT2("%s\n",kadAnalyzer.AnalyzeEmuleKadNodes(activeRouteQueryNodeList).c_str());
            DEBUG_PRINT2("%s\n",kadAnalyzer.showTypesCountOfIncomingMessages().c_str());
		}
		else if(command == 'w')
		{
			scanner.removeDuplicates();
			
			string path;
			cout<<"nodes file path:"<<endl;
			cin>>path;
			list<KadNode> peerList = scanner.GetNodeList();
			KadUtil::saveNodesInfoToFile(path,2,scanner.GetNodeList());
            path.append(".csv");
            KadUtil::writeKadNodesToCSV(scanner.GetNodeList(),path);
			cout<<endl;
			
			cout<<"sqlite file path for KadNodes:"<<endl;
			cin>>path;
			cout<<"Begin to save nodes info to database file "<<path<<endl;
			DatabaseLogger logger;
			logger.init(path);
			logger.SaveAllKadNode(scanner.GetNonBootstrapNodes());
			logger.destroy();
			DEBUG_PRINT2("%s","Save All KadNode Info to Database complete \n");
		}
		else if(command == 'q')
			break;
		else if(command == 'g')
		{
			kadCrawler.updateNodesAndCleanUp(KadUtil::kad_id,8,3);
			scanner.updateSendQueue();
			gradualCount.push_back(scanner.GetNodeList().size());
			DEBUG_PRINT2("%s","another search complete \n");
		}
		else if(command == 'r')
		{
			scanner.resetSendQueue();
			DEBUG_PRINT2("%s","reset nodes query queue \n");
		}
		else if(command == 'b')
		{
			scanner.BuildGraph();
			DEBUG_PRINT2("%s","graph building complete \n");
		}
        else if(command == 't')
        {
            showStatistics();
        }
		command = _getch();
	}
    showStatistics();
	ptime program_end_time = second_clock::local_time();
    time_duration alltime_duration = program_end_time - program_start_time;
    std::ostringstream duration_string;
    duration_string <<"Error Packets Count: "<<scanner.getUdpEngine()->error_count<<endl;
    duration_string <<"Large Unaccepted Packets Count: "<<scanner.getUdpEngine()->larget_unaccepted_count<<endl;
    duration_string <<"program running time totals "<< to_simple_string(alltime_duration)<<endl;
    DEBUG_PRINT2("%s\n",duration_string.str().c_str());
    KadLogger::Log(INFO_KAD_LOG,duration_string.str());
    Exit();
	return 0;
}
