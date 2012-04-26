#include "config.h"
#include "KadUtil.h"
#include "KadAnalyzer.h"

using namespace KadCrawl;

bool equalByID(KadNode nodeA,KadNode nodeB)
{
	return nodeA.kad_id == nodeB.kad_id;
}
bool equalByIP(KadNode nodeA,KadNode nodeB)
{
	return nodeA.ipNetOrder == nodeB.ipNetOrder;
}
KadAnalyzer::KadAnalyzer(void)
{

}
KadAnalyzer::~KadAnalyzer(void)
{

}
void KadAnalyzer::init()
{
    map<unsigned char,string>& types = types_constants;
    types.insert(make_pair(KADEMLIA_BOOTSTRAP_REQ_DEPRECATED,"KADEMLIA_BOOTSTRAP_REQ_DEPRECATED"));
    types.insert(make_pair(KADEMLIA2_BOOTSTRAP_REQ,"KADEMLIA2_BOOTSTRAP_REQ"));
    types.insert(make_pair(KADEMLIA_BOOTSTRAP_RES_DEPRECATED,"KADEMLIA_BOOTSTRAP_RES_DEPRECATED"));
    types.insert(make_pair(KADEMLIA2_BOOTSTRAP_RES,"KADEMLIA2_BOOTSTRAP_RES"));
    types.insert(make_pair(KADEMLIA_HELLO_REQ,"KADEMLIA_HELLO_REQ"));
    types.insert(make_pair(KADEMLIA_HELLO_RES,"KADEMLIA_HELLO_RES"));
    types.insert(make_pair(KADEMLIA2_HELLO_REQ,"KADEMLIA2_HELLO_REQ"));
    types.insert(make_pair(KADEMLIA2_HELLO_RES,"KADEMLIA2_HELLO_RES"));
    types.insert(make_pair(KADEMLIA_REQ,"KADEMLIA_REQ"));
    types.insert(make_pair(KADEMLIA2_REQ,"KADEMLIA2_REQ"));
    types.insert(make_pair(KADEMLIA2_HELLO_RES_ACK,"KADEMLIA2_HELLO_RES_ACK"));
    types.insert(make_pair(KADEMLIA_RES,"KADEMLIA_RES"));
    types.insert(make_pair(KADEMLIA2_RES,"KADEMLIA2_RES"));
    types.insert(make_pair(KADEMLIA_SEARCH_REQ,"KADEMLIA_SEARCH_REQ"));
    types.insert(make_pair(KADEMLIA_SEARCH_NOTES_REQ,"KADEMLIA_SEARCH_NOTES_REQ"));
    types.insert(make_pair(KADEMLIA2_SEARCH_KEY_REQ,"KADEMLIA2_SEARCH_KEY_REQ"));
    types.insert(make_pair(KADEMLIA2_SEARCH_SOURCE_REQ,"KADEMLIA2_SEARCH_SOURCE_REQ"));
    types.insert(make_pair(KADEMLIA2_SEARCH_NOTES_REQ,"KADEMLIA2_SEARCH_NOTES_REQ"));
    types.insert(make_pair(KADEMLIA_SEARCH_RES,"KADEMLIA_SEARCH_RES"));
    types.insert(make_pair(KADEMLIA_SEARCH_NOTES_RES,"KADEMLIA_SEARCH_NOTES_RES"));
    types.insert(make_pair(KADEMLIA2_SEARCH_RES,"KADEMLIA2_SEARCH_RES"));
    types.insert(make_pair(KADEMLIA_PUBLISH_REQ,"KADEMLIA_PUBLISH_REQ"));
    types.insert(make_pair(KADEMLIA_PUBLISH_NOTES_REQ,"KADEMLIA_PUBLISH_NOTES_REQ"));
    types.insert(make_pair(KADEMLIA2_PUBLISH_KEY_REQ,"KADEMLIA2_PUBLISH_KEY_REQ"));
    types.insert(make_pair(KADEMLIA2_PUBLISH_SOURCE_REQ,"KADEMLIA2_PUBLISH_SOURCE_REQ"));
    types.insert(make_pair(KADEMLIA2_PUBLISH_NOTES_REQ,"KADEMLIA2_PUBLISH_NOTES_REQ"));
    types.insert(make_pair(KADEMLIA_PUBLISH_RES,"KADEMLIA_PUBLISH_RES"));
    types.insert(make_pair(KADEMLIA_PUBLISH_NOTES_RES,"KADEMLIA_PUBLISH_NOTES_RES"));
    types.insert(make_pair(KADEMLIA2_PUBLISH_RES,"KADEMLIA2_PUBLISH_RES"));    
    types.insert(make_pair(KADEMLIA2_PUBLISH_RES_ACK,"KADEMLIA2_PUBLISH_RES_ACK"));
    types.insert(make_pair(KADEMLIA_FIREWALLED_REQ,"KADEMLIA_FIREWALLED_REQ"));
    types.insert(make_pair(KADEMLIA_FINDBUDDY_REQ,"KADEMLIA_FINDBUDDY_REQ"));
    types.insert(make_pair(KADEMLIA_CALLBACK_REQ,"KADEMLIA_CALLBACK_REQ"));
    types.insert(make_pair(KADEMLIA_FIREWALLED2_REQ,"KADEMLIA_FIREWALLED2_REQ"));
    types.insert(make_pair(KADEMLIA_FIREWALLED_RES,"KADEMLIA_FIREWALLED_RES"));
    types.insert(make_pair(KADEMLIA_FIREWALLED_ACK_RES,"KADEMLIA_FIREWALLED_ACK_RES"));
    types.insert(make_pair(KADEMLIA_FINDBUDDY_RES,"KADEMLIA_FINDBUDDY_RES"));
    types.insert(make_pair(KADEMLIA2_PING,"KADEMLIA2_PING"));
    types.insert(make_pair(KADEMLIA2_PONG,"KADEMLIA2_PONG"));
    types.insert(make_pair(KADEMLIA2_FIREWALLUDP,"KADEMLIA2_FIREWALLUDP"));
    types.insert(make_pair(KADEMLIA_FIND_VALUE,"KADEMLIA_FIND_VALUE"));
    types.insert(make_pair(KADEMLIA_STORE,"KADEMLIA_STORE"));
    types.insert(make_pair(KADEMLIA_FIND_NODE,"KADEMLIA_FIND_NODE"));
    
    unsigned long prefix_begin=1;
    unsigned long prefix_end=31;
    for(unsigned long prefix = prefix_begin;prefix<=prefix_end;prefix++)
    {
        unsigned long net_mask = KadCrawl::KadUtil::getNetmaskLongFromOrder(prefix);
        netmask_prefix_map.insert(make_pair(net_mask,prefix));
    }
}
void KadAnalyzer::compareKadPeers(std::vector<string>& seedFileList)
{
	int count = seedFileList.size();

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
	std::ostringstream stream;
	list<KadNode> intersectionList;
	list<KadNode> unionList;
	for(int i=0;i<count-1;i++)
	{
		string fileA = seedFileList[i];
		string fileB = seedFileList[i+1];

		list<KadNode> listA,listB;
		KadUtil::readKadNodesDataToList(fileA,listA);
		KadUtil::readKadNodesDataToList(fileB,listB);
		listA.sort();
		listB.sort();
		list<KadNode> difListA;
		list<KadNode> difListB;
		set_difference(listA.begin(),listA.end(),listB.begin(),listB.end(),inserter(difListA,difListA.begin()));
		set_difference(listB.begin(),listB.end(),listA.begin(),listA.end(),inserter(difListB,difListB.begin()));

		if(intersectionList.size() == 0)
			set_intersection(listA.begin(),listA.end(),listB.begin(),listB.end(),inserter(intersectionList,intersectionList.end()));
		else
		{
			list<KadNode> tempList,resultList;
			set_intersection(listA.begin(),listA.end(),listB.begin(),listB.end(),inserter(tempList,tempList.begin()));
			set_intersection(intersectionList.begin(),intersectionList.end(),tempList.begin(),tempList.end(),inserter(resultList,resultList.begin()));
			intersectionList = resultList;
		}

		set_union(listA.begin(),listA.end(),listB.begin(),listB.end(),inserter(unionList,unionList.end()));

		unsigned char firstByte = target_id.GetByteChunk(0);

		unsigned int count_samePrefixA = count_if(difListA.begin(),difListA.end(),KadCrawl::countByIDByte(target_id.GetByteChunk(0)));
		unsigned int count_samePrefixB = count_if(difListB.begin(),difListB.end(),KadCrawl::countByIDByte(target_id.GetByteChunk(0)));

		unsigned int commonShared = ((listA.size()+listB.size()-difListA.size()-difListB.size())/2);
		unsigned int commonPercentA = ((double)commonShared/(double)listA.size())*100;
		unsigned int commonPercentB = ((double)commonShared/(double)listB.size())*100;;

		stream<<difListA.size()<<"/"<<listA.size();
		stream<<" - "<<commonPercentA<<" || "<<commonShared<<" || "<<commonPercentB<<" - ";
		stream<<difListB.size()<<"/"<<listB.size()<<" *** ";
		stream<<count_samePrefixA<<" - "<<count_samePrefixB<<endl;
		DEBUG_PRINT2("%s",stream.str().c_str());
	}

	unsigned long count_samePrefixInAlive = count_if(intersectionList.begin(),intersectionList.end(),KadCrawl::countByIDByte(target_id.GetByteChunk(0)));

	KadUtil::removeDuplicates(intersectionList);
	stream<<"long time alive node size :"<<intersectionList.size()<<endl;
	stream<<"long time alive node with the same prefix size :"<<count_samePrefixInAlive<<endl;
	stream<<"all time node union size :"<<unionList.size()<<endl;
	stream<<"duplicate nodes in union size :"<<KadUtil::removeDuplicates(unionList);

	KadUtil::saveNodesInfoToFile("liveNodes.dat",2,intersectionList);
	KadUtil::saveNodesInfoToFile("unionNodes.dat",2,unionList);

    KadLogger::Log(INFO_KAD_LOG,stream.str());
}

void KadAnalyzer::compareKadPeersDir(const string& dirPath)
{
	vector<string> matchedFiles;
    const boost::regex kad_filter("^zoneNodes.*dat");
    
#ifdef BOOST_1_47
	using namespace boost::filesystem2;
#else
	using namespace boost::filesystem;
#endif
	typedef std::multimap<std::time_t,string> result_set_t;
	result_set_t result_set;
	directory_iterator end_itr;
	for(directory_iterator i(dirPath);i!=end_itr;i++)
	{
		if(!is_regular_file(i->status()))
			continue;
		boost::smatch what;
		if(!boost::regex_match(i->leaf(),what,kad_filter))
        {
             continue;
        }
		const path& pf = (*i).path();
		string pathname = pf.string();

		result_set.insert(result_set_t::value_type(last_write_time(*i),pathname));
	}

	result_set_t::iterator it = result_set.begin();
	for(;it!=result_set.end();it++)
	{
		matchedFiles.push_back(it->second);
	}
    
	compareKadPeers(matchedFiles);
}

void KadAnalyzer::AnalyzeEmuleKadNodeSessionLogInDir(std::vector<string> fileList)
{
    compareKadPeers(fileList);
}
void KadAnalyzer::AnalyzeEmuleKadNodeSessionLogInDir(string dir_path)
{
	compareKadPeersDir(dir_path);
}

void KadAnalyzer::AnalyzeEmuleKadZoneDir(string dirPath)
{
    vector<string> matchedFiles = KadCrawl::KadUtil::getFileListOfDirectory("^KadNode.*dat",dirPath);
	int count = matchedFiles.size();

	std::ostringstream stream; 
	stream<<"zone crawl result:"<<endl;
	for(int i=0;i<count;i++)
	{
		string filePath = matchedFiles[i];

		list<KadNode> nodeList;
		KadUtil::readKadNodesDataToList(filePath,nodeList);
		nodeList.sort();

		unsigned long id_count = count_if(nodeList.begin(),nodeList.end(),KadCrawl::countByIDByte(i));
		stream<<id_count<<"  ";
	}
	KadLogger::Log(INFO_KAD_LOG,stream.str());
	DEBUG_PRINT2("%s",stream.str().c_str());
}

int ipCountCmp(const std::pair<unsigned long,unsigned long>&x,const std::pair<unsigned long,unsigned long>&y)
{
	return x.second > y.second;
}
int idCountCmp(const std::pair<CUInt128,vector<KadNode> >&x,const std::pair<CUInt128,vector<KadNode> >&y)
{
	return x.second.size() > y.second.size();
}
/**
 * @brief statistically analyze specific kad node list,output result to console
 *
 * @Param nodeList kademlia network node list
 * @Param zone_index specific 8 bit zone index of kad network
 */
void KadAnalyzer::AnalyzeKadZoneNodesList(const list<KadNode>& nodeList,unsigned char zone_index)
{
    std::ostringstream stream;
    list<KadNode> localList = nodeList;
    KadUtil::removeDuplicates(localList);
    stream<<endl;
    stream<<"Size of Nodes in Zone Search Area "<<(unsigned int)zone_index<<" "<<localList.size()<<endl;;    
    localList.sort(KadCrawl::compareByKadIP);
    list<KadNode> localIPList = localList;
    localIPList.erase(unique(localIPList.begin(),localIPList.end(),KadCrawl::equalByKadIP),localIPList.end());
    stream<<"Size of Unique IP in Zone Search Area "<<(unsigned int)zone_index<<" "<<localIPList.size()<<endl;
    list<KadNode> localIDList = localList;
    localIDList.erase(unique(localIDList.begin(),localIDList.end(),KadCrawl::equalByKadID),localIDList.end());
    stream<<"Size of Unique ID in Zone Search Area "<<(unsigned int)zone_index<<" "<<localIDList.size()<<endl;

    list<KadNode> zone_list; 
    for(list<KadNode>::iterator it = localList.begin();it!=localList.end();it++)
    {
        KadNode node = *it;
        if(node.kad_id.GetByteChunk(0)==zone_index)
        {
            zone_list.push_back(node);
        }
    }
    stream<<endl; 
    stream<<"Size of Nodes in Particular Zone "<<(unsigned int)zone_index<<" "<<zone_list.size()<<endl;;    
    list<KadNode> zone_IPList = zone_list;
    KadCrawl::KadUtil::removeDuplicates(zone_IPList,KadCrawl::compareByKadIP,KadCrawl::equalByKadIP);
    stream<<"Size of Unique IP in Particular Zone "<<(unsigned int)zone_index<<" "<<zone_IPList.size()<<endl;
    list<KadNode> zone_IDList = zone_list;
    KadCrawl::KadUtil::removeDuplicates(zone_IPList,KadCrawl::compareByKadID,KadCrawl::equalByKadID);
    stream<<"Size of Unique ID in Particular Zone "<<(unsigned int)zone_index<<" "<<zone_IDList.size()<<endl;

    KadLogger::Log(INFO_KAD_LOG,stream.str());
    return;
}

string KadAnalyzer::CountVersionOfNodes(const list<KadNode>& nodeList)
{
    std::ostringstream stream;
    stream<<"version statistics of nodes file"<<endl;
	vector<unsigned long> versionStat;
    for(int i=0;i<=9;i++)
    {
        unsigned long count = count_if(nodeList.begin(),nodeList.end(),countVersion(i));
        unsigned long count_live = count_if(nodeList.begin(),nodeList.end(),countVersionAndLiveState(i));
        unsigned long count_unmatched = count_if(nodeList.begin(),nodeList.end(),countVersionAndUnmatchedState(i));
        versionStat.push_back(count);
        stream<<count<<":"<<count_live<<"  "<<count_unmatched<<endl;
    }
    stream<<"%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"<<endl;
    for(unsigned int i=0;i<=9;i++)
    {
        stream<<"Version : "<<i<<endl;
        list<KadNode> tempList = KadCrawl::KadUtil::extractNodesFromNodeListByVersion(nodeList,i);
        stream<<KadCrawl::KadUtil::DumpNodesIPGeoInfo(tempList);
        stream<<"*************************************************"<<endl;
    }
    stream<<"%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"<<endl;
    return stream.str();
}
int udpInfoCmp(const UDPPortResultType &x,const UDPPortResultType &y)
{
	return x.second.get<0>() > y.second.get<0>();
}
string KadAnalyzer::CountUDPPortOfNodes(const list<KadNode>& nodeList,unsigned int show_count)
{
    std::ostringstream stream;
    stream<<"udp port statistics of nodes file"<<endl;
	vector<unsigned long> versionStat;
    UDPPortCountMap port_count_vector;
    vector<unsigned long> count_map;
    vector<unsigned long> count_live_map;
    vector<unsigned long> count_unmatched_map;
    count_map.assign(65536,0);
    count_live_map.assign(65536,0);
    count_unmatched_map.assign(65536,0);
    for(list<KadNode>::const_iterator it = nodeList.begin();it != nodeList.end();it++)    
    {
        KadNode node = *it;
        count_map[node.udp_port]++;    
        if(node.state == KAD_ALIVE)
            count_live_map[node.udp_port]++;
        else if(node.state == KAD_UNMATCHED)
            count_unmatched_map[node.udp_port]++;
    }
    for(unsigned int i=0;i<65536;i++)
    {
        boost::tuple<unsigned int,unsigned int,unsigned int> count_result(count_map[i],count_live_map[i],count_unmatched_map[i]);
        port_count_vector.push_back(make_pair(i,count_result));
    }
    
    sort(port_count_vector.begin(),port_count_vector.end(),udpInfoCmp);

    for(unsigned int i=0;i<show_count;i++)
    {
        UDPPortResultType& result = port_count_vector[i];  
        unsigned short udp_port = result.first;
        unsigned int count = result.second.get<0>();
        unsigned int count_live = result.second.get<1>();
        unsigned int count_unmatched = result.second.get<2>();
        stream<<"The "<<i<<"th port: "<<udp_port<<" -- "<<count<<" "<<count_live<<" "<<count_unmatched<<endl;
    }
    return stream.str();
}
string KadAnalyzer::CountEightBitZoneStatOfNodes(const list<KadNode>& nodeList)
{
    std::ostringstream stream;
    stream<<"zone prefix statistics of nodes file"<<endl;
	vector<unsigned long> zonePrefixCount;
    /*
	for(int i=0;i<256;i++)
	{
		unsigned long count = count_if(nodeList.begin(),nodeList.end(),countByIDByte(i));
		unsigned long count_live = count_if(nodeList.begin(),nodeList.end(),countByIDByteAndLiveState(i));
		unsigned long count_unmatched = count_if(nodeList.begin(),nodeList.end(),countByIDByteAndUnmatchedState(i));
		zonePrefixCount.push_back(count);
		stream<<count<<" : "<<count_live<<" "<<count_unmatched<<endl;
	}
    */
    vector<unsigned long> count_map;
    vector<unsigned long> count_live_map;
    vector<unsigned long> count_unmatched_map;
    count_map.assign(256,0);
    count_live_map.assign(256,0);
    count_unmatched_map.assign(256,0);

    vector<unsigned long> version_vec;
    version_vec.assign(10,0);

    vector<vector<unsigned long> > count_version_map;
    count_version_map.assign(256,version_vec);
    vector<vector<unsigned long> > count_version_live_map;
    count_version_live_map.assign(count_version_map.begin(),count_version_map.end());
    vector<vector<unsigned long> > count_version_unmatched_map;
    count_version_unmatched_map.assign(count_version_map.begin(),count_version_map.end());
    
    unsigned int invalid_version_size = 0;
    for(list<KadNode>::const_iterator it = nodeList.begin();it!=nodeList.end();it++)
    {
        KadNode node = *it;
        uint8 zone_num = node.kad_id.GetByteChunk(0);
        count_map[zone_num]++;
        vector<unsigned long>& sub_map = count_version_map[zone_num];
        if(node.version > 9)
        {
            //DEBUG_PRINT2("node version larger than 9 : %u\n",node.version);
            invalid_version_size++;
            continue;
        }
        sub_map[node.version]++;
        if(node.state == KAD_ALIVE)
        {
            count_live_map[zone_num]++;
            count_version_live_map[zone_num][node.version]++;
        }
        else if(node.state == KAD_UNMATCHED)
        {
            count_unmatched_map[zone_num]++;
            count_version_unmatched_map[zone_num][node.version]++;
        }
    }
    
    unsigned int version_size=10;
	for(int i=0;i<256;i++)
	{
		unsigned long count = count_map[i];
		unsigned long count_live = count_live_map[i];
		unsigned long count_unmatched = count_unmatched_map[i];
		zonePrefixCount.push_back(count);
		stream<<count<<" : "<<count_live<<" "<<count_unmatched<<endl;

        stream<<"       ";
        for(unsigned int j=0;j<version_size;j++)
            stream<<count_version_map[i][j]<<" ";
        stream<<endl;

        stream<<"       ";
        for(unsigned int j=0;j<version_size;j++)
            stream<<count_version_live_map[i][j]<<" ";
        stream<<endl;

        stream<<"       ";
        for(unsigned int j=0;j<version_size;j++)
            stream<<count_version_unmatched_map[i][j]<<" ";
        stream<<endl;
	}
    DEBUG_PRINT2("size of nodes with invalid version:  %u\n",invalid_version_size);
    return stream.str();
}
unsigned long KadAnalyzer::getStatisticsByIPPrefix(const list<KadNode>& nodeList,unsigned long prefix)
{
    list<SimpleKadNode> ipmask_list = KadCrawl::KadUtil::convertToSimpleNode(nodeList);
    return getStatisticsByIPPrefix(ipmask_list,prefix);
}
unsigned long KadAnalyzer::getStatisticsByIPPrefix(const list<SimpleKadNode>& nodeList_param,unsigned long prefix)
{
    if(prefix>32)
    {
        return 0;
    }
    list<SimpleKadNode> nodeList = nodeList_param;
    unsigned long net_mask = KadCrawl::KadUtil::getNetmaskLongFromOrder(prefix);
    list<SimpleKadNode>::iterator simple_it = nodeList.begin();
    for(;simple_it != nodeList.end();simple_it++)
    {
        SimpleKadNode& node = *simple_it;
        node.ipNetOrder = htonl((ntohl(node.ipNetOrder) & net_mask));
    }
    KadCrawl::KadUtil::removeDuplicates(nodeList,KadCrawl::compareByKadIP,KadCrawl::equalByKadIP);
    return nodeList.size();
}
// Calculating statistics for replicated id list
IDCountVecType KadAnalyzer::getIDStatisticMapGeneric(const list<KadNode>& nodeList_param)
{
    list<KadNode> nodeList = nodeList_param;
// Calculating statistics for replicated id list
	list<KadNode> replicatedIDNodeList = KadCrawl::KadUtil::extractDuplicates(nodeList,KadCrawl::compareByKadID,KadCrawl::equalByKadID);
	replicatedIDNodeList.sort(KadCrawl::compareByKadID);
            
	countKadNodeIDMap idReplicatesMap;
	CUInt128 current_id;
	list<KadNode>::iterator it = replicatedIDNodeList.begin();
	
	if(it != replicatedIDNodeList.end())
	{
		KadNode node = *it;
		current_id = node.kad_id;
		idReplicatesMap[current_id].push_back(node);
		it++;
	}
	for(it=replicatedIDNodeList.begin();it!=replicatedIDNodeList.end();it++)
	{
		KadNode& node = *it;
		if(current_id == node.kad_id)
		{
			idReplicatesMap[current_id].push_back(node);
		}
		else
		{
			current_id = it->kad_id;
			idReplicatesMap[current_id].push_back(*it);
		}
	}

	IDCountVecType idCountVec;
	countKadNodeIDMap::iterator id_itMap = idReplicatesMap.begin();
	while(id_itMap != idReplicatesMap.end())
	{
		idCountVec.push_back(make_pair(id_itMap->first,id_itMap->second));
		id_itMap++;
	}
	sort(idCountVec.begin(),idCountVec.end(),idCountCmp);
    return idCountVec;
}
// Calculating statistics for replicated id list
IPCountVecType KadAnalyzer::getIPStatisticMapGeneric(const list<KadNode>& nodeList_param)
{
    countKadNodeMap map;
    list<KadNode> replicatedIPNodeList;
    list<KadNode> nodeList = nodeList_param;
    replicatedIPNodeList = KadCrawl::KadUtil::extractDuplicates(nodeList,KadCrawl::compareByKadIP,KadCrawl::equalByKadIP);

	countKadNodeMap ipReplicatesMap;
	unsigned long current_addr=0;
	list<KadNode>::iterator it = replicatedIPNodeList.begin();
	if(it != replicatedIPNodeList.end())
	{
        KadNode& node = *it;
		current_addr = node.ipNetOrder;
		ipReplicatesMap[current_addr]=2;
		it++;
	}
	for(it=replicatedIPNodeList.begin();it!=replicatedIPNodeList.end();it++)
	{
		KadNode& node = *it;
		if(current_addr == node.ipNetOrder)
		{
			ipReplicatesMap[current_addr]++;
		}
		else
		{
			current_addr = node.ipNetOrder;
			ipReplicatesMap[current_addr]=2;
		}
	}

    // Calculating statistics for replicated ip list
	vector<pair<unsigned long,unsigned long> > ipCountVec;
	countKadNodeMap::iterator itMap = ipReplicatesMap.begin();
	while(itMap != ipReplicatesMap.end())
	{
		ipCountVec.push_back(make_pair(itMap->first,itMap->second));
		itMap++;
	}

	sort(ipCountVec.begin(),ipCountVec.end(),ipCountCmp);
    return ipCountVec;
}
IP2VersionCount KadAnalyzer::getIP2VersionMap(const list<KadNode>& nodeList_param)
{
    IP2VersionCount ip_version_count_map;
    vector<unsigned long> version_vector;
    version_vector.assign(10,0);
    for(list<KadNode>::const_iterator it = nodeList_param.begin();it != nodeList_param.end();it++)
    {
        KadNode node = *it;
        IP2VersionCount::iterator it_version_map = ip_version_count_map.find(node.ipNetOrder);
        if(it_version_map != ip_version_count_map.end())
        {
            if(node.version < 10)
                it_version_map->second[node.version]++;
        }
        else
        {
            ip_version_count_map.insert(make_pair(node.ipNetOrder,version_vector));
        }
    }
    return ip_version_count_map;
}
IP2StateCount KadAnalyzer::getIP2StateMap(const list<KadNode>& nodeList_param)
{
    IP2StateCount ip_state_count_map;    
    vector<unsigned long> state_count_new;
    state_count_new.assign(3,0);
    for(list<KadNode>::const_iterator it=nodeList_param.begin();it!=nodeList_param.end();it++)
    {
        KadNode node = *it;
        IP2StateCount::iterator it_map = ip_state_count_map.find(node.ipNetOrder);
        if(it_map == ip_state_count_map.end())
        {
            ip_state_count_map.insert(make_pair(node.ipNetOrder,state_count_new));
            continue;
        }
        it_map->second[node.state - KAD_DEAD]++;
    }
    
    return ip_state_count_map;
}

IDString2StateCountMap KadAnalyzer::getID2StateMap(const list<KadNode>& nodeList_param)
{
    IDString2StateCountMap id2stateMap;
    vector<unsigned long> state_vector_new;
    state_vector_new.assign(3,0);
    
    for(list<KadNode>::const_iterator it=nodeList_param.begin();it!=nodeList_param.end();it++)
    {
        KadNode node = *it;
        IDString2StateCountMap::iterator it_map = id2stateMap.find(node.kad_id.ToHexString());
        if(it_map == id2stateMap.end())
        {
            id2stateMap.insert(make_pair(node.kad_id.ToHexString(),state_vector_new));
        }
        else
        {
            vector<unsigned long> & state_vector = it_map->second;
            state_vector[node.state-KAD_DEAD]++;
        }
    }
    return id2stateMap;
}

string KadAnalyzer::getIDStatisticMap(const list<KadNode>& nodeList_param)
{
    list<KadNode> nodeList = nodeList_param;
    std::ostringstream stream;	
    IDCountVecType idCountVec = getIDStatisticMapGeneric(nodeList_param);
	stream<<"count duplicate kad nodes by ID : "<<idCountVec.size()<<endl;
	unsigned int idNum=0;
	unsigned int showNum=20;

    IDString2StateCountMap id2stateMap = getID2StateMap(nodeList_param);

	for(vector<pair<CUInt128,vector<KadNode> > >::iterator it=idCountVec.begin();it!=idCountVec.end();it++)
	{
		stream<<"	"<<it->first.ToHexString()<<" :"<<it->second.size()<<endl;
		vector<KadNode> nodesInRep = it->second;
        vector<unsigned long>& state_count = id2stateMap[it->first.ToHexString()];
        double active_size = state_count[KAD_ALIVE-KAD_DEAD];
        stream<<"       active size: "<<active_size<<"     "<<active_size/(double)it->second.size()<<endl;
        double unmatched_size = state_count[KAD_UNMATCHED-KAD_DEAD];
        stream<<"       unmatched size: "<<unmatched_size<<"    "<<unmatched_size/(double)it->second.size()<<endl;
		for(vector<KadNode>::iterator it_rep = nodesInRep.begin();it_rep!=nodesInRep.end();it_rep++)
		{
            unsigned long ip = it_rep->ipNetOrder;
			stream<<"			"<<inet_ntoa(*((in_addr*)&ip))<<":"<<it_rep->udp_port<<" ";
            stream<<KadUtil::getFullIpGeoInfoFromIP(ip);
            if(it_rep->state==KAD_ALIVE)
                stream<<" Alive"<<endl;
            else if(it_rep->state==KAD_DEAD)
                stream<<" Dead"<<endl;
            else if(it_rep->state==KAD_UNMATCHED)
                stream<<" unmatched"<<endl;
		}
		idNum++;
		if(idNum>showNum)
			break;
	}
    return stream.str();
}
string KadAnalyzer::getIPStatisticMap(const list<KadNode>& nodeList_param)
{
    std::map<unsigned long,unsigned long> ip_livecount_map;
    std::map<unsigned long,unsigned long> ip_unmatched_count_map;

    IP2VersionCount ip_version_count_map = getIP2VersionMap(nodeList_param);
    IP2StateCount ip_state_count = getIP2StateMap(nodeList_param);
    IPCountVecType ipCountVec = getIPStatisticMapGeneric(nodeList_param);

    std::ostringstream stream;
	stream<<"count duplicate kad nodes by IP "<<endl;
    stream<<"   the size of distinct ip addresses which has duplicates : "<<ipCountVec.size()<<endl;
    stream<<"   the size of distinct ip addresses of all nodes : "<<ip_version_count_map.size()<<endl;
	unsigned int ipNum=0;
	unsigned int showNum=20;

	for(vector<pair<unsigned long,unsigned long> >::iterator it_ipCount=ipCountVec.begin();it_ipCount!=ipCountVec.end();it_ipCount++)
	{
        unsigned long ip = it_ipCount->first;
        unsigned long count = it_ipCount->second;
        vector<unsigned long>& state_vec = ip_state_count[ip];
		stream<<"	"<<inet_ntoa(*((in_addr*)&ip))<<" : "<<count<<" - "<<state_vec[KAD_ALIVE-KAD_DEAD]<<" - "<<state_vec[KAD_UNMATCHED-KAD_DEAD]<<" ";
        stream<<"$$version: ";
        vector<unsigned long> ip_version_vector = ip_version_count_map[ip];
        for(unsigned int i=0;i<ip_version_vector.size();i++)
        {
            stream<<ip_version_vector[i]<<" ";    
        }
        stream<<KadCrawl::KadUtil::getFullIpGeoInfoFromIP(ip)<<endl;
		ipNum++;
		if(ipNum > showNum)
			break;
	}
    return stream.str();
}   
string KadAnalyzer::AnalyzeKadActiveCount(const list<KadNode>& nodeList_param,unsigned int maximum_show_size)
{
    list<KadNode> nodeList = nodeList_param;     

    std::map<unsigned long,unsigned long> activeCount_size_map;

    list<KadNode> subList = KadCrawl::KadUtil::extractSubList(nodeList,KadCrawl::compareByKadSurvivalCount,nodeList.size());
    nodeList.clear();
    std::ostringstream stream;
    stream<<"Kad Nodes Survival Count: "<<endl;
    unsigned int count=1;
    for(list<KadNode>::iterator it = subList.begin();it != subList.end();it++)
    {
        const KadNode& node = *it;
        map<unsigned long,unsigned long>::iterator it_map = activeCount_size_map.find(node.count);
        if(it_map == activeCount_size_map.end())
        {
            activeCount_size_map.insert(make_pair(node.count,1));
        }
        else
            it_map->second++;
    }
    for(list<KadNode>::iterator it = subList.begin();it != subList.end() && count > maximum_show_size;it++)
    {
        const KadNode& node = *it;
        count++;
        stream<<"   "<<node.count<<"    ";
        if(node.state == KAD_DEAD)
            stream<<"dead  ";
        else if(node.state == KAD_ALIVE)
            stream<<"alive ";
        else if(node.state == KAD_UNMATCHED)
            stream<<"unmatched ";
        unsigned long ip = node.ipNetOrder;
        stream<<inet_ntoa(*((in_addr*)&ip))<<":"<<node.udp_port<<" ";
        stream<<KadUtil::getFullIpGeoInfoFromIP(ip)<<endl;
    }

    stream<<"respond count statistics"<<endl;
    std::map<unsigned long,unsigned long>::iterator it_show_map = activeCount_size_map.begin();
    // 0-10,10-100,100-1000,1000-10000
    std::vector<unsigned long> nodes_count;
    nodes_count.assign(4,0);
    while(it_show_map != activeCount_size_map.end())
    {
        unsigned long respond_count = it_show_map->first;
        unsigned long respond_count_size = it_show_map->second;
        stream<<respond_count<<" :  "<<respond_count_size<<endl;
        if(respond_count < 10)
            nodes_count[0]+=respond_count_size;
        else if(respond_count >= 10 && respond_count < 100)
            nodes_count[1]+=respond_count_size;
        else if(respond_count >= 100 && respond_count < 1000)
            nodes_count[2]+=respond_count_size;
        else if(respond_count >= 1000)
            nodes_count[3]+=respond_count_size;
        it_show_map++;
    }
    stream<<endl;
    stream<<"count by range: "<<endl;
    stream<<"0-10    "<<nodes_count[0]<<endl;
    stream<<"10-100    "<<nodes_count[1]<<endl;
    stream<<"100-1000    "<<nodes_count[2]<<endl;
    stream<<"1000-10000    "<<nodes_count[3]<<endl;
    return stream.str();
}

string KadAnalyzer::AnalyzeEmuleKadNodes(list<KadNode>& nodeList)
{
    std::ostringstream stream;
    stream<<"********************************************************"<<endl;
    stream<<"Total Kad Nodes Size: "<<nodeList.size()<<endl;
    DEBUG_PRINT1("Begin To Compute Active History Statistics of Kad Nodes\n");
    stream<<AnalyzeKadActiveCount(nodeList,20)<<endl;
    DEBUG_PRINT1("Begin To Dump Ip Geoinfo of Nodes\n");
    stream<<KadCrawl::KadUtil::DumpNodesIPGeoInfo(nodeList)<<endl;
    DEBUG_PRINT1("Begin To Count Node Version Info\n");
	stream<<CountVersionOfNodes(nodeList)<<endl;
    DEBUG_PRINT1("Begin To Count Node Zone Info\n");
	stream<<CountEightBitZoneStatOfNodes(nodeList)<<endl;
    DEBUG_PRINT1("Begin To Count IP Info\n");
    stream<<getIPStatisticMap(nodeList)<<endl;
    DEBUG_PRINT1("Begin To Count ID Info\n");
    stream<<getIDStatisticMap(nodeList)<<endl;
    DEBUG_PRINT1("Begin To Count UDP Ports Info\n");
    stream<<CountUDPPortOfNodes(nodeList,20)<<endl;
    DEBUG_PRINT1("Begin To Count IP Prefix Info\n");
    stream<<"Distinct C Net Size: ";
    stream<<getStatisticsByIPPrefix(nodeList,24)<<endl;
    for(unsigned int i=16;i<24;i++)
    {
        stream<<"Prefix "<<i<<" : "<<getStatisticsByIPPrefix(nodeList,i)<<endl;      
    }
    stream<<endl;
    stream<<"########################################################"<<endl;
	KadLogger::Log(INFO_KAD_LOG,stream.str());
    return stream.str();
}
string KadAnalyzer::AnalyzeSimpleKadNodes(list<SimpleKadNode>& nodeList_param)
{
    list<KadNode> nodeList = KadCrawl::KadUtil::expandToFullKadNode(nodeList_param);
    std::ostringstream stream;
    stream<<"********************************************************"<<endl;
    stream<<"Total Simple Kad Nodes Size: "<<nodeList.size()<<endl;
    stream<<KadCrawl::KadUtil::DumpNodesIPGeoInfo(nodeList)<<endl;
	stream<<CountEightBitZoneStatOfNodes(nodeList)<<endl;
    stream<<getIPStatisticMap(nodeList)<<endl;
    stream<<getIDStatisticMap(nodeList)<<endl;
    stream<<"Distinct C Net Size: ";
    stream<<getStatisticsByIPPrefix(nodeList,24)<<endl;
    for(unsigned int i=16;i<24;i++)
    {
        stream<<"Prefix "<<i<<" : "<<getStatisticsByIPPrefix(nodeList,i)<<endl;      
    }
    stream<<endl;
    stream<<"########################################################"<<endl;
	KadLogger::Log(INFO_KAD_LOG,stream.str());
    return stream.str();
}

/**
 * @brief Statistically analyze particular node file of kad network
 *
 * @Param file_path path of kad nodes file
 */
void KadAnalyzer::AnalyzeEmuleKadNodesFile(string file_path)
{
	list<KadNode> nodeList;
	KadUtil::readKadNodesDataToList(file_path,nodeList);
    list<KadNode> dupNodeList = KadUtil::extractDuplicates(nodeList);
    unsigned int limit=10;
    unsigned int count=1;
    ostringstream duplicate_stream;
    duplicate_stream<<"duplicate items: "<<endl;
    for(list<KadNode>::iterator it = dupNodeList.begin();it!=dupNodeList.end();it++)
    {
        KadNode& node = *it;
        duplicate_stream<<node.dumpInfo();
        count++;
        if(count > limit)
            break;
    }
    KadLogger::Log(INFO_KAD_LOG,duplicate_stream.str());

    unsigned int liveNum=0;
    unsigned int unmatched=0;
    for(list<KadNode>::iterator it = nodeList.begin();it != nodeList.end();it++)
    {
        KadNode& node = *it;
        if(node.state == KAD_ALIVE)
            liveNum++;
        if(node.state == KAD_UNMATCHED)
            unmatched++;
    }
    ostringstream live_stream;
    live_stream<<"active items: "<<endl;
    live_stream<<liveNum<<endl;;
    live_stream<<"unmatched items: "<<endl;
    live_stream<<unmatched<<endl;    
    KadLogger::Log(INFO_KAD_LOG,live_stream.str());

    KadUtil::removeDuplicates(nodeList); 
    DEBUG_PRINT2("%s\n",AnalyzeEmuleKadNodes(nodeList).c_str());
}
/**
 * @brief Statistically analyze particular node file with specified zone index of kad network
 *
 * @Param file_path path of kad nodes file
 * @Param zone index
 */
void KadAnalyzer::AnalyzeEmuleKadNodesFileInSpecifiedZone(string file_path,unsigned int zone_index)
{
	list<KadNode> nodeList;
	KadUtil::readKadNodesDataToList(file_path,nodeList);

    unsigned int liveNum=0;
    unsigned int unmatchedNum=0;
    for(list<KadNode>::iterator it = nodeList.begin();it != nodeList.end();)
    {
        KadNode& node = *it;
        if(node.kad_id.GetByteChunk(0)!=zone_index)
        {
            it = nodeList.erase(it);
            continue;
        }
        else
            it++;
        if(node.state == KAD_ALIVE)
            liveNum++;
        if(node.state == KAD_UNMATCHED)
            unmatchedNum++;
    }
    ostringstream live_stream;
    live_stream<<"active items:  "<<liveNum<<" ";
    live_stream<<"unmatched items:  "<<unmatchedNum<<endl;

    KadLogger::Log(INFO_KAD_LOG,live_stream.str());

    KadUtil::removeDuplicates(nodeList); 
    DEBUG_PRINT2("%s\n",AnalyzeEmuleKadNodes(nodeList).c_str());
}
void KadAnalyzer::AnalyzeEmuleKadNodesFileInSpecifiedCountry(string file_path,string country)
{
	list<KadNode> nodeList;
	KadUtil::readKadNodesDataToList(file_path,nodeList);

    unsigned int liveNum=0;
    unsigned int unmatchedNum=0;
    for(list<KadNode>::iterator it = nodeList.begin();it != nodeList.end();)
    {
        KadNode& node = *it;
        string country_node = KadCrawl::KadUtil::getCountryNameFromIP(node.ipNetOrder);
        if(country_node != country)
        {
            it = nodeList.erase(it);
            continue;
        }
        else
            it++;
        if(node.state == KAD_ALIVE)
            liveNum++;
        if(node.state == KAD_UNMATCHED)
            unmatchedNum++;
    }
    ostringstream live_stream;
    live_stream<<"active items:  "<<liveNum<<" ";
    live_stream<<"unmatched items:  "<<unmatchedNum<<endl;

    KadLogger::Log(INFO_KAD_LOG,live_stream.str());

    KadUtil::removeDuplicates(nodeList); 
    DEBUG_PRINT2("%s\n",AnalyzeEmuleKadNodes(nodeList).c_str());
}
void KadAnalyzer::AnalyzeEmuleKadNodesFileWithSpecifiedVersion(string file_path,unsigned int version_param)
{
	list<KadNode> nodeList;
	KadUtil::readKadNodesDataToList(file_path,nodeList);

    unsigned int liveNum=0;
    unsigned int unmatchedNum=0;
    for(list<KadNode>::iterator it = nodeList.begin();it != nodeList.end();)
    {
        KadNode& node = *it;
        unsigned int version = node.version;
        if(version != version_param)
        {
            it = nodeList.erase(it);
            continue;
        }
        else
            it++;
        if(node.state == KAD_ALIVE)
            liveNum++;
        if(node.state == KAD_UNMATCHED)
            unmatchedNum++;
    }
    ostringstream live_stream;
    live_stream<<"active items:  "<<liveNum<<" ";
    live_stream<<"unmatched items:  "<<unmatchedNum<<endl;

    KadLogger::Log(INFO_KAD_LOG,live_stream.str());

    KadUtil::removeDuplicates(nodeList); 
    DEBUG_PRINT2("%s\n",AnalyzeEmuleKadNodes(nodeList).c_str());
        
}
string KadAnalyzer::AnalyzeLiveKadNodes(list<KadNode>& nodeList,list<SimpleKadNode>& tempNodeList)
{
	nodeList.sort();
	tempNodeList.sort();

	unsigned long liveNum=0;
	std::ostringstream stream;

	list<SimpleKadNode>::iterator it = tempNodeList.begin();
	for(;it!=tempNodeList.end();it++)
	{
		SimpleKadNode& node = *it;
		if(binary_search(nodeList.begin(),nodeList.end(),node))
		{
			liveNum++;
		}
	}
	double percentage = ((double)liveNum/(double)nodeList.size())*100;
	stream<<"live nodes size:  "<<liveNum<<"  percentage "<<percentage<<"%"<<endl;
	return stream.str();
}

void KadAnalyzer::AppendNodeListSnapshot(const list<KadNode>& nodeList)
{
    nodeListSnapList.push_back(nodeList);
}
string KadAnalyzer::AnalyzeNodeListSnapShotsAsZoneCrawl(unsigned char zone_index)
{
    std::ostringstream stream;
    stream<<endl;
    for(unsigned int i=1;i<nodeListSnapList.size();i++)
    {
        stream<<"******************************"<<endl;
        list<KadNode> previous_nodeListUnion;
        list<KadNode> nodesSnap = nodeListSnapList[i];
        for ( unsigned int j=0 ; j<i ; j++ )
        {
            previous_nodeListUnion.insert(previous_nodeListUnion.end(),nodeListSnapList[j].begin(),nodeListSnapList[j].end());
        }
        KadUtil::removeDuplicates(previous_nodeListUnion); 

        list<KadNode> diff_nodeList,diff_IPList,diff_IDList;
        nodesSnap.sort();
        previous_nodeListUnion.sort();
        set_difference(nodesSnap.begin(),nodesSnap.end(),previous_nodeListUnion.begin(),previous_nodeListUnion.end(),inserter(diff_nodeList,diff_nodeList.begin()));
        nodesSnap.sort(KadCrawl::compareByKadIP);
        previous_nodeListUnion.sort(KadCrawl::compareByKadIP);
        set_difference(nodesSnap.begin(),nodesSnap.end(),previous_nodeListUnion.begin(),previous_nodeListUnion.end(),inserter(diff_IPList,diff_IPList.begin()),KadCrawl::compareByKadIP);
        nodesSnap.sort(KadCrawl::compareByKadID);
        previous_nodeListUnion.sort(KadCrawl::compareByKadID);
        set_difference(nodesSnap.begin(),nodesSnap.end(),previous_nodeListUnion.begin(),previous_nodeListUnion.end(),inserter(diff_IDList,diff_IDList.begin()),KadCrawl::compareByKadID);
        
        stream<<"Round "<<i<<" Newly discovered node size "<<diff_nodeList.size()<<endl;
        stream<<"Round "<<i<<" Newly discovered ip size "<<diff_IPList.size()<<endl;        
        stream<<"Round "<<i<<" Newly discovered id size "<<diff_IDList.size()<<endl;        
        stream<<"*****************************"<<endl;
    }
    return stream.str();
}
string KadAnalyzer::AnalyzeCollectionOfKadNodeList(vector<list<KadNode> >& nodeList_param)
{
    if(nodeList_param.size() == 0)
        return "";
    vector<list<SimpleKadNode> > nodeListVector; 
    for(unsigned int i=0;i<nodeList_param.size();i++)
    {
        nodeListVector.push_back(KadCrawl::KadUtil::convertToSimpleNode(nodeList_param[i]));    
    }
    nodeList_param.clear();

    list<SimpleKadNode> alltime_live_nodeList=nodeListVector[0];
    list<SimpleKadNode> alltime_union_nodeList=nodeListVector[0];
    KadUtil::removeDuplicates(alltime_live_nodeList);
    KadUtil::removeDuplicates(alltime_union_nodeList);
    for(unsigned int i=1;i<nodeListVector.size();i++)
    {
        list<SimpleKadNode> tempIntersecList;
        list<SimpleKadNode> tempUnionList;
        set_intersection(alltime_live_nodeList.begin(),alltime_live_nodeList.end(),nodeListVector[i].begin(),nodeListVector[i].end(),inserter(tempIntersecList,tempIntersecList.end()));
        set_union(alltime_union_nodeList.begin(),alltime_union_nodeList.end(),nodeListVector[i].begin(),nodeListVector[i].end(),inserter(tempUnionList,tempUnionList.end()));
        alltime_live_nodeList = tempIntersecList;
        alltime_union_nodeList = tempUnionList;
        KadUtil::removeDuplicates(alltime_live_nodeList);
        KadUtil::removeDuplicates(alltime_union_nodeList);
    }

    std::ostringstream stream;
    stream<<"Intersection Node Size (compare all): "<<alltime_live_nodeList.size()<<endl;
    stream<<"Union Node Size (compare all): "<<alltime_union_nodeList.size()<<endl;
    alltime_live_nodeList.clear();
    alltime_union_nodeList.clear();

    KadCrawl::KadUtil::removeDuplicates(nodeListVector[0],KadCrawl::compareByKadIP,KadCrawl::equalByKadIP);
    list<SimpleKadNode> alltime_liveip_nodeList = nodeListVector[0];
    list<SimpleKadNode> alltime_unionliveip_nodeList = nodeListVector[0];
    for ( unsigned int i=1 ; i<nodeListVector.size() ; i++ )
    {
        list<SimpleKadNode> tempIntersecList;
        list<SimpleKadNode> tempUnionList;
        KadCrawl::KadUtil::removeDuplicates(nodeListVector[i],KadCrawl::compareByKadIP,KadCrawl::equalByKadIP);
        set_intersection(alltime_liveip_nodeList.begin(),alltime_liveip_nodeList.end(),nodeListVector[i].begin(),nodeListVector[i].end(),inserter(tempIntersecList,tempIntersecList.end()),KadCrawl::compareByKadIP);
        set_union(alltime_unionliveip_nodeList.begin(),alltime_unionliveip_nodeList.end(),nodeListVector[i].begin(),nodeListVector[i].end(),inserter(tempUnionList,tempUnionList.end()),KadCrawl::compareByKadIP);
        alltime_liveip_nodeList = tempIntersecList;
        alltime_unionliveip_nodeList = tempUnionList;
    }
    
    stream<<"Intersection Node Size(compare IP): "<<alltime_liveip_nodeList.size()<<endl;
    stream<<"Union Node Size(compare IP): "<<alltime_unionliveip_nodeList.size()<<endl;
    return stream.str();
}

string KadAnalyzer::AnalyzeRepititionOfKadNodeListByPathList(vector<string> path_list)
{
    if(path_list.size() == 0)
        return "";
    std::ostringstream stream;
    list<KadNode> nodeList;
    KadCrawl::KadUtil::readKadNodesDataToList(path_list[0],nodeList);
    list<SimpleKadNode> alltime_live_nodeList = KadCrawl::KadUtil::convertToSimpleNode(nodeList);
    list<SimpleKadNode> alltime_union_nodeList=alltime_live_nodeList;
    KadUtil::removeDuplicates(alltime_live_nodeList);
    KadUtil::removeDuplicates(alltime_union_nodeList);
    for(unsigned int i=1;i<path_list.size();i++)
    {
        list<KadNode> nextTempNodeList;
        KadCrawl::KadUtil::readKadNodesDataToList(path_list[i],nextTempNodeList); 
        list<SimpleKadNode> nextNodeList = KadCrawl::KadUtil::convertToSimpleNode(nextTempNodeList);
        nextTempNodeList.clear();

        list<SimpleKadNode> tempIntersecList;
        list<SimpleKadNode> tempUnionList;
        set_intersection(alltime_live_nodeList.begin(),alltime_live_nodeList.end(),nextNodeList.begin(),nextNodeList.end(),inserter(tempIntersecList,tempIntersecList.end()));
        set_union(alltime_union_nodeList.begin(),alltime_union_nodeList.end(),nextNodeList.begin(),nextNodeList.end(),inserter(tempUnionList,tempUnionList.end()));
        alltime_live_nodeList = tempIntersecList;
        alltime_union_nodeList = tempUnionList;
        KadUtil::removeDuplicates(alltime_live_nodeList);
        KadUtil::removeDuplicates(alltime_union_nodeList);

        std::ostringstream local_stream;
        local_stream<<"Currently alltime_live_nodeList size: "<<alltime_live_nodeList.size()<<endl; 
        local_stream<<"Currently union_nodeList size: "<<alltime_union_nodeList.size()<<endl;
        string output = local_stream.str();
        DEBUG_PRINT2("%s",output.c_str());
        stream<<output;
    }

    stream<<"Intersection Node Size (compare all): "<<alltime_live_nodeList.size()<<endl;
    stream<<"Union Node Size (compare all): "<<alltime_union_nodeList.size()<<endl;
    alltime_live_nodeList.clear();
    alltime_union_nodeList.clear();
    return stream.str();
}
string KadAnalyzer::AnalyzeIPRepititionOfKadNodeListByPathList(vector<string> path_list)
{
    list<KadNode> nodeList;
    if(path_list.size()==0)
        return "No file to Analyze IP";
    KadCrawl::KadUtil::readKadNodesDataToList(path_list[0],nodeList);

    std::ostringstream stream;    
    KadCrawl::KadUtil::removeDuplicates(nodeList,KadCrawl::compareByKadIP,KadCrawl::equalByKadIP);
    list<SimpleKadNode> alltime_liveip_nodeList = KadCrawl::KadUtil::convertToSimpleNode(nodeList);
    list<SimpleKadNode> alltime_unionliveip_nodeList = alltime_liveip_nodeList;
    unsigned long union_increment = 0;
    unsigned long union_cnet_increment=0;
    unsigned long current_union_cnet_size=0;
    unsigned long total_count = path_list.size();
    for ( unsigned int i=1 ; i<total_count ; i++ )
    {
        DEBUG_PRINT3("the %uth of %u file begin to process\n",i,(unsigned int)path_list.size());
        using namespace boost::posix_time;
    	ptime begin_time = second_clock::local_time();
        list<KadNode> nextTempNodeList;
        KadCrawl::KadUtil::readKadNodesDataToList(path_list[i],nextTempNodeList);
        list<SimpleKadNode> nextNodeList = KadCrawl::KadUtil::convertToSimpleNode(nextTempNodeList);
        nextTempNodeList.clear();

        list<SimpleKadNode> tempIntersecList;
        list<SimpleKadNode> tempUnionList;
        KadCrawl::KadUtil::removeDuplicates(nextNodeList,KadCrawl::compareByKadIP,KadCrawl::equalByKadIP);
        set_intersection(alltime_liveip_nodeList.begin(),alltime_liveip_nodeList.end(),nextNodeList.begin(),nextNodeList.end(),inserter(tempIntersecList,tempIntersecList.end()),KadCrawl::compareByKadIP);
        set_union(alltime_unionliveip_nodeList.begin(),alltime_unionliveip_nodeList.end(),nextNodeList.begin(),nextNodeList.end(),inserter(tempUnionList,tempUnionList.end()),KadCrawl::compareByKadIP);
        union_increment = tempUnionList.size()-alltime_unionliveip_nodeList.size();
        alltime_liveip_nodeList = tempIntersecList;
        alltime_unionliveip_nodeList = tempUnionList;
    	ptime end_time = second_clock::local_time();
        time_duration alltime_duration = end_time-begin_time;
        ostringstream stream;
        stream<<"this file consumed time totals "<< to_simple_string(alltime_duration)<<endl;
        DEBUG_PRINT2("%s",stream.str().c_str());
        /*
        unsigned long c_net_size = getStatisticsByIPPrefix(alltime_unionliveip_nodeList,24);
        union_cnet_increment = c_net_size - current_union_cnet_size;
        current_union_cnet_size = c_net_size;

        std::ostringstream local_stream;
        local_stream<<"Currently alltime_liveip_nodeList size: "<<alltime_liveip_nodeList.size()<<endl; 
        local_stream<<"Currently unionliveip_nodeList size: "<<alltime_unionliveip_nodeList.size()<<endl;
        local_stream<<"Currently union nodes distinct C Net Size: ";
        local_stream<<c_net_size<<endl;
        if(union_cnet_increment > union_increment)
        {
            local_stream<<"Warning: C Net Increment exceeds IP Increment with "<<union_cnet_increment<<" vs "<<union_increment<<endl<<endl;
        }
        string output = local_stream.str();
        DEBUG_PRINT2("%s\n",output.c_str());
        stream<<output;
        */
    }
    KadCrawl::KadUtil::saveNodesInfoToDefaultPathWithPrefix("ip_intersection",2,(const list<KadNode>&)alltime_liveip_nodeList);
    KadCrawl::KadUtil::saveNodesInfoToDefaultPathWithPrefix("ip_union",2,(const list<KadNode>&)alltime_unionliveip_nodeList);
    KadCrawl::KadUtil::saveIPOfNodeListToPath("onlyip_intersection",alltime_liveip_nodeList);
    KadCrawl::KadUtil::saveIPOfNodeListToPath("onlyip_union",alltime_unionliveip_nodeList);
    stream<<"Intersection Node Size(compare IP): "<<alltime_liveip_nodeList.size()<<endl;
    stream<<"Union Node Size(compare IP): "<<alltime_unionliveip_nodeList.size()<<endl;
    return stream.str();
}
void KadAnalyzer::countCNetStatistics(string path)
{
    map<unsigned long,unsigned long> ipMap;
    unsigned int netmask_order=24;
    list<KadNode> nodeList;
    KadCrawl::KadUtil::readKadNodesDataToList(path,nodeList);
    unsigned long netmask = KadCrawl::KadUtil::getNetmaskLongFromOrder(netmask_order);
    for(list<KadNode>::iterator it = nodeList.begin();it != nodeList.end();it++)
    {
        KadNode& node = *it;
        unsigned long c_net_addr = KadCrawl::KadUtil::convertIPtoMaskedIP(node.ipNetOrder,netmask);
        map<unsigned long,unsigned long>::iterator c_net_it = ipMap.find(c_net_addr);
        if(c_net_it == ipMap.end())
        {
            ipMap[c_net_addr]=1;
        }
        else
        {
            c_net_it->second++;
        }    
    }
}
void KadAnalyzer::countIncomingMessageType(unsigned char type)
{
    map<unsigned char,unsigned long>::iterator it = messageIncomingMap.find(type);
    if(it == messageIncomingMap.end())
    {
        messageIncomingMap[type]=1;    
    }
    else
    {
        it->second++;
    }
}
int typesCountCmp(const std::pair<unsigned char,unsigned long>&x,const std::pair<unsigned char,unsigned long>&y)
{
	return x.second > y.second;
}
string KadAnalyzer::showTypesCountOfIncomingMessages()
{
    map<unsigned char,string>& types = types_constants;
    vector<pair<unsigned char,unsigned long> > types_count;
	map<unsigned char,unsigned long>::iterator itMap = messageIncomingMap.begin();
	while(itMap != messageIncomingMap.end())
	{
		types_count.push_back(make_pair(itMap->first,itMap->second));
		itMap++;
	}

	sort(types_count.begin(),types_count.end(),typesCountCmp);
    
    std::ostringstream stream;
    stream<<"Kad Incoming Message Type Statistics"<<endl;
    for(unsigned int i=0;i<types_count.size();i++) 
    {
		pair<unsigned char,unsigned long> type_count = types_count[i];
        unsigned char type = type_count.first;
        unsigned long count = type_count.second;
        std::ostringstream type_string;        
        map<unsigned char,string>::iterator it = types.find(type);
        if(it == types.end())
        {
            //char type_hex[10]={0};
            //sprintf(type_hex,"%021X",(ULONG)type));
            type_string << "type in hex: " <<((unsigned int)type);
        }
        else
        {
            type_string << (it->second);
        }
        stream<<count<<"            "<<type_string.str()<<endl; 
    }
    return stream.str();
}

list<KadNode> KadAnalyzer::findNodesByIP(const list<KadNode>& nodeList_param,unsigned long ip,unsigned int netmask_order)
{
    list<KadNode> foundNodes;
    list<SearchKadNode> nodeList = KadCrawl::KadUtil::convertToSearchKadNode(nodeList_param);
    KadCrawl::KadUtil::convertIPWithNetmask(nodeList,netmask_order);
    nodeList.sort(KadCrawl::compareByKadIP);
    ip = KadCrawl::KadUtil::netmaskIPLong(ip,netmask_order);
    SearchKadNode seedNode;
    seedNode.ipNetOrder = ip;    
    std::pair<list<SearchKadNode>::iterator,list<SearchKadNode>::iterator> matched_pair = equal_range(nodeList.begin(),nodeList.end(),seedNode,KadCrawl::compareByKadIP);
    if(matched_pair.first!=nodeList.end())
    {
        list<SearchKadNode>::iterator it_match = matched_pair.first;
        while(it_match != matched_pair.second)
        {
            SearchKadNode& node = *it_match;
            if(node.ipNetOrder == ip)
            {
                KadNode normal_node(node.kad_id,node.full_ip,node.udp_port,node.tcp_port,KadCrawl::KadUtil::kad_id,node.version,node.kadUDPkey,node.verified,node.parentIpAddr);
                foundNodes.push_back(normal_node);
            }
            it_match++;
        }
        if(it_match == matched_pair.second)
        {
            SearchKadNode& node = *it_match;
            if(node.ipNetOrder == ip)
            {
                KadNode normal_node(node.kad_id,node.full_ip,node.udp_port,node.tcp_port,KadCrawl::KadUtil::kad_id,node.version,node.kadUDPkey,node.verified,node.parentIpAddr);
                foundNodes.push_back(normal_node);
            }
        }
    }
    return foundNodes;
}
list<KadNode> KadAnalyzer::findNodesByIP(const list<KadNode>& nodeList,string ip,unsigned int netmask)
{
    unsigned long ip_long = inet_addr(ip.c_str());
    return findNodesByIP(nodeList,ip_long,netmask);
}
/**
 * @brief enumerate node list file in a directory limited by last write time and count
 *
 * @Param directory directory of node files
 * @Param ip ip address
 * @Param netmask netmask to filter nodes
 * @Param elapsed_minutes time elapsed since last write
 *
 * @return Kad nodes found 
 */
list<KadNode> KadAnalyzer::findNodesByIPInDirectory(string directory,string prefix_filter,string ip,unsigned int netmask,unsigned int elapsed_minutes)
{
    vector<string> matchedFiles = KadCrawl::KadUtil::getFileListOfDirectoryTimeLimited(directory,prefix_filter,2000,elapsed_minutes);
    int count = matchedFiles.size();

    list<KadNode> matchedNodeList;
	std::ostringstream stream; 
	stream<<"find nodes by ip in directory"<<endl;
    stream<<matchedFiles.size()<<" files found"<<endl;
	for(int i=0;i<count;i++)
	{
		string filePath = matchedFiles[i];
        stream<<filePath<<" :"<<endl;
		list<KadNode> nodeList;
		KadUtil::readKadNodesDataToList(filePath,nodeList);

        list<KadNode> nodeListTemp = findNodesByIP(nodeList,ip,netmask);
        for(list<KadNode>::iterator it = nodeListTemp.begin();it != nodeListTemp.end();it++)
        {
            KadNode node = *it;
            stream<<"      "<<node.dumpInfo()<<endl;
        }
        stream<<endl;
        matchedNodeList.insert(matchedNodeList.end(),nodeListTemp.begin(),nodeListTemp.end());
	}
	KadLogger::Log(INFO_KAD_LOG,stream.str());
	DEBUG_PRINT2("%s",stream.str().c_str());
    return matchedNodeList;
}
list<KadNode> KadAnalyzer::findNodesByIPInDirectoryByQuantile(string directory,string prefix_filter,string ip,unsigned int netmask,unsigned int quantile_begin_int,unsigned int quantile_end_int,unsigned int maximum_files)
{
    vector<boost::tuple<string,time_t> > matchedFiles = KadCrawl::KadUtil::getFileListOfDirectoryByTimeQuantile(directory,prefix_filter,quantile_begin_int,quantile_end_int,maximum_files);
    int count = matchedFiles.size();

    list<KadNode> matchedNodeList;
	std::ostringstream stream; 
	stream<<"find nodes by ip in directory"<<endl;
    stream<<matchedFiles.size()<<" files found"<<endl;
	for(int i=0;i<count;i++)
	{
		string filePath = matchedFiles[i].get<0>();
        stream<<filePath<<" :"<<endl;
		list<KadNode> nodeList;
		KadUtil::readKadNodesDataToList(filePath,nodeList);

        list<KadNode> nodeListTemp = findNodesByIP(nodeList,ip,netmask);
        for(list<KadNode>::iterator it = nodeListTemp.begin();it != nodeListTemp.end();it++)
        {
            KadNode node = *it;
            stream<<"      "<<node.dumpInfo()<<endl;
        }
        stream<<endl;
        matchedNodeList.insert(matchedNodeList.end(),nodeListTemp.begin(),nodeListTemp.end());
	}
	KadLogger::Log(INFO_KAD_LOG,stream.str());
	DEBUG_PRINT2("%s",stream.str().c_str());
    return matchedNodeList;
}
CompactSessionNodeMap KadAnalyzer::getLiveSessionStatisticsCompactWithOptionalCountryCode(string directory,string prefix_filter,unsigned long maximum_files,unsigned int elapsed_minutes,string country_code)
{
    vector<boost::tuple<string,time_t> > matchedFiles = KadCrawl::KadUtil::getFileListOfDirectoryInternal(directory,prefix_filter,maximum_files,elapsed_minutes);
    CompactSessionNodeMap NodeSessionData;
    for(unsigned int i=0;i<matchedFiles.size();i++)
	{
		string filePath = matchedFiles[i].get<0>();
		time_t modified_time = matchedFiles[i].get<1>();
        MD5 md5_gen;
        list<KadNode> nodeList;
        if(country_code == "ZZ")
            KadCrawl::KadUtil::readKadNodesDataToList(filePath,nodeList);
        else
            KadCrawl::KadUtil::readKadNodesDataToListWithCountrySpecified(filePath,nodeList,country_code);
        list<SimpleKadNode> snodeList = KadCrawl::KadUtil::convertToSimpleNode(nodeList);
        for (list<SimpleKadNode>::iterator it=snodeList.begin(); it!=snodeList.end() ; it++)
        {
            uint8 md5sum[16]={0};
            SimpleKadNode node = *it;
            md5_gen.Update((unsigned char*)&node,sizeof(SimpleKadNode));
            md5_gen.Final(md5sum);
            vector<char> node_key(md5sum,md5sum+sizeof(uint8)*16);
            CompactSessionNodeMap::iterator exist_node_it = NodeSessionData.find(node_key);
            if(exist_node_it == NodeSessionData.end())
            {
                NodeSessionData.insert(std::pair<vector<char>,unsigned long>(node_key,1));
            }
            else
            {
                exist_node_it->second++;
            }
        }
    }		
    return NodeSessionData;
}
SessionNodeMap KadAnalyzer::getLiveSessionStatisticsGeneric(vector<boost::tuple<string,time_t> > matchedFiles)
{
    SessionNodeMap NodeSessionData;
    for(unsigned int i=0;i<matchedFiles.size();i++)
	{
		string filePath = matchedFiles[i].get<0>();
		time_t modified_time = matchedFiles[i].get<1>();
        MD5 md5_gen;
        list<KadNode> nodeList;
        KadCrawl::KadUtil::readKadNodesDataToList(filePath,nodeList);
        list<SimpleKadNode> snodeList = KadCrawl::KadUtil::convertToSimpleNode(nodeList);
        for (list<SimpleKadNode>::iterator it=snodeList.begin(); it!=snodeList.end() ; it++)
        {
            uint8 md5sum[16]={0};
            SimpleKadNode node = *it;
            md5_gen.Update((unsigned char*)&node,sizeof(SimpleKadNode));
            md5_gen.Final(md5sum);
            vector<char> node_key(md5sum,md5sum+sizeof(uint8)*16);
            SessionNodeMap::iterator exist_node_it = NodeSessionData.find(node_key);
            if(exist_node_it == NodeSessionData.end())
            {
                SessionKadNode session_node;    
                session_node.ipNetOrder = node.ipNetOrder;
                session_node.kad_id = node.kad_id;
                session_node.udp_port = node.udp_port;
                session_node.livePeriods.push_back(i);
                NodeSessionData.insert(std::pair<vector<char>,SessionKadNode>(node_key,session_node));
            }
            else
            {
                SessionKadNode& exist_node = exist_node_it->second;
                exist_node.livePeriods.push_back(i);
            }
        }
    }		
    return NodeSessionData;
}
SessionNodeMap KadAnalyzer::getLiveSessionStatistics(string directory,string prefix_filter,unsigned long maximum_files,unsigned int elapsed_minutes)
{
    vector<boost::tuple<string,time_t> > matchedFiles = KadCrawl::KadUtil::getFileListOfDirectoryInternal(directory,prefix_filter,maximum_files,elapsed_minutes);
    return getLiveSessionStatisticsGeneric(matchedFiles);
}
string KadAnalyzer::loadIPHistoryStatisticsFromFile(string filename)
{
    KadCrawl::KadUtil::LoadObject<AllIPCountMap>(filename,ip_count_map);
    DEBUG_PRINT3("File %s loaded, nodes size %u\n",filename.c_str(),ip_count_map.size());
    ostringstream stream;
    AllIPCountMap::iterator it_show_all = ip_count_map.begin();
    DEBUG_PRINT2("netmask_prefix_map size : %u\n",netmask_prefix_map.size());
    while(it_show_all != ip_count_map.end())
    {
        stream<<"   ";
        unsigned long netmask = it_show_all->first;
        IPCountMap& map = it_show_all->second;
        std::map<unsigned long,unsigned long>::iterator found_mask;
        found_mask = netmask_prefix_map.find(netmask);
        if(found_mask != netmask_prefix_map.end())
        {
            stream<<found_mask->second<<" size:  "<<map.size()<<endl;
        }
        it_show_all++;
    }
    DEBUG_PRINT2("%s\n",stream.str().c_str());
    KadLogger::Log(INFO_KAD_LOG,stream.str());
    DEBUG_PRINT2("Finished loading file %s\n",filename.c_str());
    return stream.str();
}
string KadAnalyzer::getIPHistoryStatisticsGeneric(vector<boost::tuple<string,time_t> > matchedFiles,unsigned long prefix_begin,unsigned long prefix_end,const KadFilter& pass_filter,const KadFilter& block_filter)
{
    if(prefix_begin > 32 || prefix_begin < 1)
        return "Invalid prefix_begin";
    if(prefix_end > 32 || prefix_end < 1)
        return "Invalid prefix_end";
    if(prefix_begin > prefix_end)
        return "prefix_begin bigger than prefix_end";
    vector<unsigned long> netmask_array;
    for(unsigned long prefix = prefix_begin;prefix<=prefix_end;prefix++)
    {
        unsigned long net_mask = KadCrawl::KadUtil::getNetmaskLongFromOrder(prefix);
        netmask_array.push_back(net_mask);
    }
    ostringstream output_stream;
    for(unsigned int i=0;i<matchedFiles.size();i++)
	{
		string filePath = matchedFiles[i].get<0>();
		time_t modified_time = matchedFiles[i].get<1>();
        list<KadNode> nodeList;
        KadCrawl::KadUtil::readKadNodesDataToList(filePath,nodeList);
        unsigned long count = 0;
        unsigned long total_count = nodeList.size();
        for(list<KadNode>::iterator it = nodeList.begin();it!=nodeList.end();it++)
        {
            count++;
            KadNode& node = *it;
            if(!KadCrawl::KadUtil::checkFilter(node,pass_filter))
                continue;
            if(!KadCrawl::KadUtil::checkOrBlockFilter(node,block_filter))
                continue;
            unsigned long ipaddr = node.ipNetOrder;
            for(unsigned j=0;j < netmask_array.size();j++)
            {
                unsigned long netmask = netmask_array[j];
                unsigned long ip = htonl((ntohl(ipaddr) & netmask));
                AllIPCountMap::iterator found_all_it = ip_count_map.find(netmask);
                if(found_all_it != ip_count_map.end())
                {
                    IPCountMap& ipCountMap = found_all_it->second;
                    IPCountMap::iterator found_it = ipCountMap.find(ip);        
                    
                    if(found_it == ipCountMap.end())
                    {
                        vector<unsigned long> ip_state;
                        ip_state.assign(3,0);
                        //0 size;1 live size;2 unmatched size
                        ip_state[node.state-KAD_DEAD]=1;
                        ipCountMap.insert(make_pair(ip,ip_state));
                    }
                    else
                    {
                        found_it->second[node.state-KAD_DEAD]++;    
                    }
                }
                else
                {
                    IPCountMap map;
                    ip_count_map.insert(make_pair(netmask,map));
                }
            }
        }
        unsigned int coherent_count=0;
        ostringstream stream;
        AllIPCountMap::iterator it_show_all = ip_count_map.begin();
        stream<<"The "<<i<<" th file: "<<endl;
        while(it_show_all != ip_count_map.end())
        {
            stream<<"   ";
            unsigned long netmask = it_show_all->first;
            IPCountMap& map = it_show_all->second;
            std::map<unsigned long,unsigned long>::iterator found_mask;
            found_mask = netmask_prefix_map.find(netmask);
            if(found_mask != netmask_prefix_map.end())
            {
                stream<<found_mask->second<<" size:  "<<map.size()<<endl;
            }
            it_show_all++;
        }
        DEBUG_PRINT2("%s\n",stream.str().c_str());
        KadLogger::Log(INFO_KAD_LOG,stream.str());
        output_stream<<stream.str();
    }        
    KadCrawl::KadUtil::SaveObject<AllIPCountMap>("./log/nodes_ip_history.dat",ip_count_map);

    ostringstream stream;
    AllIPCountMap::iterator it_show_all = ip_count_map.begin();
    while(it_show_all != ip_count_map.end())
    {
        stream<<"   ";
        unsigned long netmask = it_show_all->first;
        IPCountMap& map = it_show_all->second;
        std::map<unsigned long,unsigned long>::iterator found_mask;
        found_mask = netmask_prefix_map.find(netmask);
        unsigned int prefix=0;
        if(found_mask != netmask_prefix_map.end())
        {
            prefix = found_mask->second;
            stream<<prefix<<" size:  "<<map.size()<<endl;
        }

        IPCountMap::iterator it_ip_count_map = map.begin();
        unsigned int coherent_live_count=0;
        unsigned int coherent_dead_count=0;
        unsigned int more_live_than_dead_count=0;
        unsigned int unmatched_count=0;
        while(it_ip_count_map != map.end())
        {
            unsigned long ip = it_ip_count_map->first;
            vector<unsigned long> state_count = it_ip_count_map->second;
            if(state_count[1]!=0 && state_count[0]==0 && state_count[2]==0)
                coherent_live_count++;
            if(state_count[0]!=0 && state_count[1]==0 && state_count[2]==0)
                coherent_dead_count++;
            if(state_count[0]<state_count[1])
                more_live_than_dead_count++;
            it_ip_count_map++;
        }
        stream<<"       coherent live count: "<<coherent_live_count<<"    "<<(double)coherent_live_count*100/(double)map.size()<<"%"<<endl;
        stream<<"       coherent dead count: "<<coherent_dead_count<<"    "<<(double)coherent_dead_count*100/(double)map.size()<<"%"<<endl;
        stream<<"       more live than dead count: "<<more_live_than_dead_count<<"    "<<(double)more_live_than_dead_count*100/(double)map.size()<<"%"<<endl;
        it_show_all++;
    }
    DEBUG_PRINT2("%s\n",stream.str().c_str());
    KadLogger::Log(INFO_KAD_LOG,stream.str());
    return output_stream.str();
}
int sessionInfoCmp(const SessionKadNode& x,const SessionKadNode& y)
{
	return x.livePeriods.size()>y.livePeriods.size();
}
string KadAnalyzer::dumpSessionStatistics(SessionNodeMap& map,unsigned long maximum_files)
{
    std::ostringstream stream;
    SessionNodeMap::iterator it = map.begin();    
    vector<SessionKadNode> sessionNodes;
    while(it != map.end())
    {
        SessionKadNode& node = it->second;
        sessionNodes.push_back(node);
        it++;
    }
    sort(sessionNodes.begin(),sessionNodes.end(),sessionInfoCmp);
    //sessionNodes.sort();
    unsigned long new_incoming_nodes = 0;
    vector<SessionKadNode>::iterator it_session_list = sessionNodes.begin();
    unsigned long node_withhole_size=0;
    while(it_session_list != sessionNodes.end())
    {
        SessionKadNode& node = *it_session_list;
        if(node.livePeriods.size()!=maximum_files)
        {
            stream<<inet_ntoa((*(in_addr*)&node.ipNetOrder))<<"  "<<node.livePeriods.size()<<endl;
            stream<<"       "<<node.livePeriods[0]<<"--"<<node.livePeriods[node.livePeriods.size()-1]<<" missing:   ";
            unsigned int current_count=node.livePeriods[0]+1;
            bool with_hole=false;
            for(unsigned int i=1;i<node.livePeriods.size();i++)
            {
                if(current_count!=node.livePeriods[i])            
                {
                    while(current_count!=node.livePeriods[i])
                    {
                        stream<<current_count<<" ";
                        current_count++;
                    }
                    with_hole=true;
                }
                current_count++;
            }
            if(with_hole)
                node_withhole_size++;
            stream<<endl;
        }
        it_session_list++;
    }
    stream<<"nodes with hole : "<<node_withhole_size<<endl;
    return stream.str();
}
string KadAnalyzer::dumpCompactSessionStatistics(CompactSessionNodeMap& map)
{
    std::ostringstream stream;
    CompactSessionNodeMap::iterator it = map.begin();    
    vector<unsigned long> sessionNodes;
    while(it != map.end())
    {
        sessionNodes.push_back(it->second);
        it++;
    }
    sort(sessionNodes.begin(),sessionNodes.end(),std::greater<unsigned long>());
    //sessionNodes.sort();
    unsigned long current_size_statistics=1;
    unsigned long current_size=sessionNodes[0];
    stream<<endl;
    for(unsigned int i=1;i<sessionNodes.size();i++)
    {
        unsigned long temp_size = sessionNodes[i];
        if(temp_size == current_size)
            current_size_statistics++;
        else
        {
            stream<<current_size<<"  "<<current_size_statistics<<endl;
            current_size = temp_size;
            current_size_statistics=1;
        }
    }
    stream<<current_size<<"  "<<current_size_statistics<<endl;
    return stream.str();
}
