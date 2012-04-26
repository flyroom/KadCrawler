#include "config.h"
#include "KadUtil.h"
#include "DatabaseLogger.h"
#include "boost/date_time/local_time_adjustor.hpp"
#include "boost/date_time/c_local_time_adjustor.hpp"

using namespace KadCrawl;

CryptoPP::AutoSeededRandomPool cryptRandomGen;
CUInt128 KadUtil::kad_id=(ULONG)0;
CUInt128 KadUtil::client_hash=(ULONG)0;

GeoIP* KadUtil::gi=NULL;
GeoIP* KadUtil::gi_as=NULL;
GeoIP* KadUtil::gi_city=NULL;

uint32 KadUtil::udpVerifyKey=0;
CIpInfo* KadUtil::qqIpEngine=NULL;
string KadUtil::log_directory="log";
unsigned short KadUtil::udp_port=UDP_SERVER_PORT;
vector<unsigned long> KadUtil::duplicateCountVector;

bool KadCrawl::compareByKadID(SimpleKadNode aNode,SimpleKadNode bNode)
{
	return aNode.kad_id < bNode.kad_id;
}

bool KadCrawl::compareByKadIP(SimpleKadNode aNode,SimpleKadNode bNode)
{
	return aNode.ipNetOrder < bNode.ipNetOrder;
}

bool KadCrawl::equalByKadIP(SimpleKadNode aNode,SimpleKadNode bNode)
{
	return aNode.ipNetOrder == bNode.ipNetOrder;
}

bool KadCrawl::equalByKadID(SimpleKadNode aNode,SimpleKadNode bNode)
{
	return aNode.kad_id == bNode.kad_id;
}

bool KadCrawl::compareByKadSurvivalCount(KadNode& nodeA,KadNode& nodeB)
{
    return nodeA.count > nodeB.count;
}

KadUtil::KadUtil(void)
{
}

KadUtil::~KadUtil(void)
{
}

void KadUtil::Init()
{
			
    setRandomKadID();
	// Generate per user hash to identify itself in other node's rout table,use pregenerated one here
	unsigned char userhash[16]={186,59,194,230,161,14,227,76,101,151,221,45,142,57,111,163};
	/*
	CryptoPP::AutoSeededRandomPool rng;
	rng.GenerateBlock(userhash,16);
	userhash[5]=14;
	userhash[14]=111;
	*/

	client_hash.SetValue(userhash);

	gi = GeoIP_new(GEOIP_STANDARD);
    if(gi== NULL)
    {
        KadLogger::Log(INFO_KAD_LOG,"GeoIP Library Init Failed");
    }
    else
    {
        KadLogger::Log(INFO_KAD_LOG,"GeoIP Library Init Successfully");
    }
    gi_as = GeoIP_open("GeoIPASNum.dat",GEOIP_STANDARD);
    if(gi_as == NULL)
    {
        KadLogger::Log(INFO_KAD_LOG,"GeoIP AsNum Library Init Failed");
    }
    else
    {
        KadLogger::Log(INFO_KAD_LOG,"GeoIP AsNum Library Init Successfully");
    }
    gi_city = GeoIP_open("GeoLiteCity.dat",GEOIP_STANDARD);
    if(gi_city == NULL)
    {
        KadLogger::Log(INFO_KAD_LOG,"GeoLiteCity Library Init Failed");
    }
    else
    {
        KadLogger::Log(INFO_KAD_LOG,"GeoLiteCity Library Init Successfully");
    }
    const char* qqIpFilePath = "qqwry.dat";
    qqIpEngine = new CIpInfo();
    qqIpEngine->LoadInfoFile(qqIpFilePath);
    if(qqIpEngine->IsInitialed())
    {
        KadLogger::Log(INFO_KAD_LOG,"QQWry Lib Init Successfully");
    }
    else{
        KadLogger::Log(INFO_KAD_LOG,"QQWry Lib Init Failed");
    }
using namespace boost::filesystem;
    if(!exists(KadCrawl::KadUtil::log_directory))
    {
        create_directory(KadCrawl::KadUtil::log_directory);   
        KadLogger::Log(DEBUG_KAD_LOG,"Create Log Directory for storing log files");
    }
}
void KadUtil::setRandomKadID()
{
    kad_id = udpVerifyKey = cryptRandomGen.GenerateWord32(0,0xFFFFFFFF);
	kad_id.SetValueRandom();
}
void KadUtil::setIDByKeyword(string keyword)
{
	kad_id = getInt128FromString(keyword);
}
/**
 * @brief release resource
 */
void KadUtil::Destroy()
{
	if(gi != NULL)
	{
		GeoIP_delete(gi);
		gi = NULL;
	}
    if(gi_as != NULL)
    {
        GeoIP_delete(gi_as);
        gi_as = NULL;
    }
    GeoIP_cleanup();
}
int KadUtil::readKadNodesDataToListEx(string filepath,list<KadNode>& nodeList,unsigned int node_count,unsigned int version)
{
    ifstream fs;
	fs.open(filepath.c_str(),ios_base::binary|ios_base::in);
	if(fs.eof())
	{
		DEBUG_PRINT2("file can't open  %s",filepath.c_str());
		return -1;
	}
    fs.seekg(12,ios::beg);
    
	double start = clock();

	unsigned long kad_id_long[4]={0};
	unsigned long uIP=0;
	unsigned short udp_port=0;
	unsigned short tcp_port=0;
	unsigned char type=0;
	unsigned long kadUDPKey = 0;
	unsigned long kadUDPKeyIP=0;
	bool verified=false;
    unsigned char state;
    unsigned short count=0;

	unsigned int duplicates = 0;
	for(unsigned int i=0;i<node_count;i++)
	{
		if(version == 3)
		{
            // 34 bytes total
            fs.read((char*)kad_id_long,sizeof(unsigned long)*4);
            fs.read((char*)&uIP,sizeof(unsigned long));
            fs.read((char*)&udp_port,sizeof(udp_port));
            fs.read((char*)&tcp_port,sizeof(tcp_port));
            fs.read((char*)&type,sizeof(type));
            fs.read((char*)&kadUDPKey,sizeof(unsigned long));
            fs.read((char*)&kadUDPKeyIP,sizeof(unsigned long));
            fs.read((char*)&state,sizeof(state));
            fs.read((char*)&count,sizeof(uint16));

            KadUDPKey key(kadUDPKey,kadUDPKeyIP);

            CUInt128 node_id;
            node_id.directAssign(kad_id_long[0],kad_id_long[1],kad_id_long[2],kad_id_long[3]);
            KadNode target_node(node_id,ntohl(uIP),udp_port,tcp_port,kad_id,type,key,verified);
            target_node.state = (NODE_STATE)state;
            target_node.count = count;
            nodeList.push_back(target_node);
		}
	}
	
	//DEBUG_PRINT1(DumpNodesInfo().c_str());
	//DEBUG_PRINT1(routingZone->dumpInfo("").c_str());
	double finish = clock();
	fs.close();
	ULONG duration = (ULONG)((finish - start)/CLOCKS_PER_SEC);
	return version;
}
int KadUtil::readKadNodesDataToListOld(string filepath,list<KadNode>& nodeList,unsigned int node_count,unsigned int version)
{
    ifstream fs;
	fs.open(filepath.c_str(),ios_base::binary|ios_base::in);
	if(fs.eof())
	{
		DEBUG_PRINT2("file can't open  %s",filepath.c_str());
		return -1;
	}
    fs.seekg(12,ios::beg);
    
	double start = clock();

	unsigned long kad_id_long[4]={0};
	unsigned long uIP=0;
	unsigned short udp_port=0;
	unsigned short tcp_port=0;
	unsigned char type=0;
	unsigned long kadUDPKey = 0;
	unsigned long kadUDPKeyIP=0;
	bool verified=false;
    unsigned char state;

	unsigned int duplicates = 0;
	for(unsigned int i=0;i<node_count;i++)
	{
		if(version >= 0 && version < 3)
		{
			if(version <= 1)
			{
				fs.read((char*)kad_id_long,sizeof(unsigned long)*4);
				fs.read((char*)&uIP,sizeof(unsigned long));
				fs.read((char*)&udp_port,sizeof(udp_port));
				fs.read((char*)&tcp_port,sizeof(tcp_port));
				fs.read((char*)&type,sizeof(type));
				CUInt128 node_id;
				node_id.directAssign(kad_id_long[0],kad_id_long[1],kad_id_long[2],kad_id_long[3]);
				KadNode target_node(node_id,ntohl(uIP),udp_port,tcp_port,kad_id,type,0,false);
				nodeList.push_back(target_node);
			}
			else
			{
				// 34 bytes total
				fs.read((char*)kad_id_long,sizeof(unsigned long)*4);
				fs.read((char*)&uIP,sizeof(unsigned long));
				fs.read((char*)&udp_port,sizeof(udp_port));
				fs.read((char*)&tcp_port,sizeof(tcp_port));
				fs.read((char*)&type,sizeof(type));
				fs.read((char*)&kadUDPKey,sizeof(unsigned long));
				fs.read((char*)&kadUDPKeyIP,sizeof(unsigned long));
				fs.read((char*)&state,sizeof(state));
				
				KadUDPKey key(kadUDPKey,kadUDPKeyIP);

				CUInt128 node_id;
				node_id.directAssign(kad_id_long[0],kad_id_long[1],kad_id_long[2],kad_id_long[3]);
				KadNode target_node(node_id,ntohl(uIP),udp_port,tcp_port,kad_id,type,key,verified);
                target_node.state = (NODE_STATE)state;
								
				//routingZone->Add(&node);

				//boost::mutex::scoped_lock lock(nodeListLock);
				/*
				ContactList::iterator it = lower_bound(nodeList.begin(),nodeList.end(),target_node);
	
				if(it != nodeList.end() && *it == target_node)
				{
					duplicates++;
					continue;
				}
				*/
				//nodeList.insert(it,target_node);
				nodeList.push_back(target_node);
				
				//nodeList.sort();
				//lock.unlock();
			}
		}
	}
	
	//DEBUG_PRINT1(DumpNodesInfo().c_str());
	//DEBUG_PRINT1(routingZone->dumpInfo("").c_str());
	double finish = clock();
	fs.close();
	ULONG duration = (ULONG)((finish - start)/CLOCKS_PER_SEC);
	return version;
}
/**
 * @brief read kad nodes info to list
 *
 * @Param filepath file path 
 * @Param nodeList target node list to write 
 *
 * @return count of nodes read
 */
int KadUtil::readKadNodesDataToList(string filepath,list<KadNode>& nodeList)
{
	ifstream fs;
	fs.open(filepath.c_str(),ios_base::binary|ios_base::in);

	if(fs.eof())
	{
		DEBUG_PRINT2("file can't open  %s",filepath.c_str());
		return -1;
	}

	unsigned long node_count=0;
	unsigned int version=0;
	fs.read((char*)&node_count,sizeof(node_count));
	if(node_count==0)
	{
		fs.read((char*)&version,sizeof(version));
		fs.read((char*)&node_count,sizeof(node_count));
	}

    std::ostringstream stream;
    stream<<"Reading file "<<filepath<<" with "<<node_count<<" nodes";
    DEBUG_PRINT3("%s version %d\n",stream.str().c_str(),version);
    KadLogger::Log(INFO_KAD_LOG,stream.str());
    fs.close();

    try {
        if(version <= 2)
        {
            readKadNodesDataToListOld(filepath,nodeList,node_count,version);
        }
        else
        {
            readKadNodesDataToListEx(filepath,nodeList,node_count,version);
        }
    }
    catch(string& error)
    {
        std::ostringstream stream;
        stream<<"error while reading file "<<filepath<<"    "<<error;
        DEBUG_PRINT2("%s",stream.str().c_str());
        KadLogger::Log(WARN_KAD_LOG,stream.str());
    }
    catch (std::exception& e)
    {
        KadLogger::Log(WARN_KAD_LOG,e.what());
    }

    return version;	
}
/**
 * @brief read kad nodes info to list
 *
 * @Param filepath file path 
 * @Param nodeList target node list to write 
 * @Param country code string in two digits
 *
 * @return count of nodes read
 */
int KadUtil::readKadNodesDataToListWithCountrySpecified(string filepath,list<KadNode>& nodeList,string country_code_param)
{
    readKadNodesDataToList(filepath,nodeList);    
    unsigned int deleted = 0;
    list<KadNode>::iterator it = nodeList.begin();
    while(it != nodeList.end())
    {
        KadNode& node = *it;
        const char* country_code_array = GeoIP_country_code_by_ipnum(gi,ntohl(node.ipNetOrder));
        if(country_code_array == NULL)
        {
            it++;
            continue;
        }
        string country_code = country_code_array;
        if(country_code == country_code_param)
        {
            it++;
        }
        else
        {
            it = nodeList.erase(it);            
            deleted++;
        }
    }
    return deleted;
}
CUInt128 KadUtil::getInt128FromString(string keyword)
{
	MD4 md4_c;
	unsigned char msg[16];
	md4_c.Update((byte*)keyword.c_str(),keyword.size());
	md4_c.Final(msg);

	CUInt128 target_id;
	target_id.SetValueBE(msg);
	return target_id;
}
list<KadNode> KadUtil::GetNeighboringNodes(list<KadNode>& nodeList,CUInt128 target_id,unsigned long range)
{
	list<KadNode> tempList;
	SimpleKadNode targetNode(target_id,0,0);

	list<KadNode>::iterator mid_it= lower_bound(nodeList.begin(),nodeList.end(),targetNode,compareByKadID);
	list<KadNode>::reverse_iterator low_it(mid_it);
	list<KadNode>::iterator high_it=mid_it;

	uint32 subRange = (range+1)/2;
	while(low_it != nodeList.rend()&&subRange>0)
	{
		tempList.push_back(*low_it);
		subRange--;
		low_it++;
	}
	subRange += (range+1)/2;
	while(high_it != nodeList.end()&&subRange>0)
	{
		tempList.push_back(*high_it);
		subRange--;
		high_it++;
	}
	return tempList;
}

inline bool eq_kadnode_pip(const KadNode& nodeA,const KadNode& nodeB)
{
	return (nodeA.kad_id==nodeB.kad_id && nodeA.ipNetOrder==nodeB.ipNetOrder && nodeA.udp_port==nodeB.udp_port && nodeA.parentIpAddr==nodeB.parentIpAddr);
}

inline bool lt_kadnode_pip(const KadNode& nodeA,const KadNode& nodeB)
{
	if(!(nodeA.kad_id == nodeB.kad_id))
		return nodeA.kad_id < nodeB.kad_id;
	else if(nodeA.ipNetOrder != nodeB.ipNetOrder)
		return nodeA.ipNetOrder < nodeB.ipNetOrder;
	else if(nodeA.udp_port != nodeB.udp_port)
		return nodeA.udp_port < nodeB.udp_port;
	else
		return false;
}

unsigned int KadUtil::removeDuplicatesSustainGraphRelation(list<KadNode>& nodeList)
{
	nodeList.sort(lt_kadnode_pip);
	unsigned long erasedNum = nodeList.size();
	nodeList.erase(unique(nodeList.begin(),nodeList.end(),eq_kadnode_pip),nodeList.end());
	erasedNum -= nodeList.size();
	if(erasedNum != 0)
		duplicateCountVector.push_back(erasedNum);
	return erasedNum;
}
void KadUtil::saveNodesInfoToDefaultPath(unsigned version,const list<KadNode>& nodeList)
{
    std::ostringstream nameStream;
    nameStream<<KadCrawl::KadUtil::log_directory;
#ifdef WIN32
    nameStream<<"\\";
#else
    nameStream<<"/";
#endif
    nameStream<<"bootNodes_";
    nameStream<<getCurrentTimeString();
    nameStream<<".dat";
    saveNodesInfoToFile(nameStream.str(),version,nodeList);
}
void KadUtil::saveNodesInfoToDefaultPathWithPrefix(string prefix,unsigned version,const list<KadNode>& nodeList)
{
    std::ostringstream nameStream;
    nameStream<<KadCrawl::KadUtil::log_directory;
#ifdef WIN32
    nameStream<<"\\";
#else
    nameStream<<"/";
#endif
    nameStream<<prefix<<"_";
    nameStream<<getCurrentTimeString();
    nameStream<<".dat";
    saveNodesInfoToFile(nameStream.str(),version,nodeList);
}

void KadUtil::saveZoneNodesInfoToDefaultPath(unsigned version,const list<KadNode>& nodeList_param,unsigned char zone_index)
{
    char zone_hex[10]={0};
    sprintf(zone_hex,"%02X",(unsigned int)zone_index);
    std::ostringstream nameStream;
    nameStream<<KadCrawl::KadUtil::log_directory;
#ifdef WIN32
    nameStream<<"\\";
#else
    nameStream<<"/";
#endif
    nameStream<<"zoneNodes_";
    nameStream<<zone_hex;
    nameStream<<"_";
    nameStream<<getCurrentTimeString();
    nameStream<<".dat";
    list<KadNode> nodeList = nodeList_param;
    for(list<KadNode>::iterator it = nodeList.begin();it != nodeList.end();)
    {
        KadNode& node = *it;
        if(node.kad_id.GetByteChunk(0) != zone_index)
        {
            it = nodeList.erase(it);        
        }
        else
            it++;
    }
    saveNodesInfoToFile(nameStream.str(),version,nodeList);

}
void KadUtil::saveNodesInfoToFile(string filepath,unsigned int version,const list<KadNode>& nodeList)
{
    switch ( version )
    {
    case 1:
    case 2:
        saveNodesInfoToFileLegacy(filepath,version,nodeList);
        break;
    case 3:
        saveNodesInfoToFileDetail(filepath,version,nodeList);
        break;
    default :
        break;
    }
}
void KadUtil::saveNodesInfoToFile(string filepath,unsigned int version,const list<SimpleKadNode>& nodeList)
{
    list<KadNode> fullNodeList;
    for(list<SimpleKadNode>::const_iterator it=nodeList.begin();it!=nodeList.end();it++)
    {
        const SimpleKadNode& sNode = *it;
        KadNode node;
        node.kad_id = sNode.kad_id; 
        node.udp_port = sNode.udp_port;
        node.ipNetOrder = sNode.ipNetOrder;
        fullNodeList.push_back(node);
    }
    saveNodesInfoToFile(filepath,version,fullNodeList);
}
void KadUtil::saveNodesInfoToFileDetail(string filepath,unsigned int version,const list<KadNode>& nodeList)
{
    const ContactList& list = nodeList;
	ofstream fs;
	fs.open(filepath.c_str(),ios_base::binary|ios_base::out);
	uint32 content=0;
	fs.write((char*)&content,sizeof(content));
	content = version;
    // version
	fs.write((char*)&content,sizeof(content));
	content = list.size();
    // node size
	fs.write((char*)&content,sizeof(content));
	ContactList::const_iterator it = list.begin();
	for(;it != list.end();it++)
	{
		KadNode node = *it;
		fs.write((char*)node.kad_id.GetData(),sizeof(uint32)*4);
		uint32 ip = htonl(node.ipNetOrder);
		fs.write((char*)&ip,sizeof(uint32));
		fs.write((char*)&node.udp_port,sizeof(uint16));
		fs.write((char*)&node.tcp_port,sizeof(uint16));
		fs.write((char*)&node.version,sizeof(uint8));

		fs.write((char*)&node.kadUDPkey.m_dwKey,sizeof(uint32));
		fs.write((char*)&node.kadUDPkey.m_dwIP,sizeof(uint32));
		//fs.write((char*)&node.verified,sizeof(uint8));
		fs.write((char*)&node.state,sizeof(uint8));
		fs.write((char*)&node.count,sizeof(uint16));
	}
	fs.close();
}
void KadUtil::saveNodesInfoToFileLegacy(string filepath,unsigned int version,const list<KadNode>& nodeList)
{
	const ContactList& list = nodeList;
	ofstream fs;
	fs.open(filepath.c_str(),ios_base::binary|ios_base::out);
	uint32 content=0;
	fs.write((char*)&content,sizeof(content));
	content = version;
	fs.write((char*)&content,sizeof(content));
	content = list.size();
	fs.write((char*)&content,sizeof(uint32));
	ContactList::const_iterator it = list.begin();
	for(;it != list.end();it++)
	{
		KadNode node = *it;
		fs.write((char*)node.kad_id.GetData(),sizeof(uint32)*4);
		uint32 ip = htonl(node.ipNetOrder);
		fs.write((char*)&ip,sizeof(uint32));
		fs.write((char*)&node.udp_port,sizeof(uint16));
		fs.write((char*)&node.tcp_port,sizeof(uint16));
		fs.write((char*)&node.version,sizeof(uint8));

		if(version<2)
			continue;
		fs.write((char*)&node.kadUDPkey.m_dwKey,sizeof(uint32));
		fs.write((char*)&node.kadUDPkey.m_dwIP,sizeof(uint32));
        
		//fs.write((char*)&node.verified,sizeof(uint8));
		fs.write((char*)&node.state,sizeof(uint8));
	}

	fs.close();
}
string KadUtil::DumpNodesInfo(ContactList nodeList)
{
	std::ostringstream stream;

	list<KadNode>::iterator it = nodeList.begin();
	while(it != nodeList.end())
	{
		KadNode& node = *it;
		string info = node.dumpInfo();
		stream<<info;
		it++;
	}
	//list<KadNode>::size_type
	unsigned long count = count_if(nodeList.begin(),nodeList.end(),checkInSame8bitZone(kad_id));
	stream << endl;
	stream <<"The number of nodes which have the same prefix  "<<count<<endl;
    stream << DumpNodesIPAsInfo(nodeList);
	return stream.str();
}
KadNode* KadUtil::FindKadNodeByID(ContactList& nodeList,CUInt128 uID)
{
	ContactList::iterator it = find_if(nodeList.begin(),nodeList.end(),findKadNodeByID(uID));
	if(it != nodeList.end())
	{
		KadNode& node = *it;
		return &node;
	}
	return NULL;
}
KadNode* KadUtil::FindKadNodeByIP(ContactList& nodeList,unsigned long ip)
{
	list<KadNode>::iterator it = nodeList.begin();
	while(it != nodeList.end())
	{
		KadNode& node = *it;
		if(node.ipNetOrder == ip)
			return &node;
		it++;
	}
	return NULL;
}
/**
 * @brief ugly code must be removed once elegant way is available
 *
 * @Param nodeList list of kad nodes
 *
 * @return  Geo information of these kad nodes  
 */
map<string,unsigned long> KadUtil::GetGeoInfoFromNodeListWithMask(const list<SimpleKadNode>& nodeList,unsigned long mask)
{
	map<string,unsigned long> ipCountryCount;

	list<SimpleKadNode>::const_iterator it = nodeList.begin();
	for(;it != nodeList.end() && gi != NULL;it++)
	{
		const SimpleKadNode& node = *it;
        unsigned long masked_ip = node.ipNetOrder&mask;
		const char * country_string = GeoIP_country_code_by_addr(gi,inet_ntoa(*((in_addr*)&masked_ip)));
		if(country_string == NULL)
			continue;

		int country_id = GeoIP_id_by_addr(gi,inet_ntoa(*((in_addr*)&node.ipNetOrder)));
		const char * full_country_string = GeoIP_country_name_by_id(gi,country_id);

		string country_code = full_country_string;
		map<string,unsigned long>::iterator mapIt = ipCountryCount.find(country_code);
		if(mapIt != ipCountryCount.end())
		{
			mapIt->second++;
		}
		else
		{
			ipCountryCount[country_code]=1;
		}
	}
	return ipCountryCount;
}

map<string,unsigned long> KadUtil::GetGeoInfoFromNodeList(const list<KadNode>& nodeList)
{
	map<string,unsigned long> ipCountryCount;

	ContactList::const_iterator it = nodeList.begin();
	for(;it != nodeList.end() && gi != NULL;it++)
	{
		const KadNode& node = *it;
		const char * country_string = GeoIP_country_code_by_addr(gi,inet_ntoa(*((in_addr*)&node.ipNetOrder)));
		if(country_string == NULL)
			continue;

		int country_id = GeoIP_id_by_addr(gi,inet_ntoa(*((in_addr*)&node.ipNetOrder)));
		const char * full_country_string = GeoIP_country_name_by_id(gi,country_id);

		string country_code = full_country_string;
		map<string,unsigned long>::iterator mapIt = ipCountryCount.find(country_code);
		if(mapIt != ipCountryCount.end())
		{
			mapIt->second++;
		}
		else
		{
			ipCountryCount[country_code]=1;
		}
	}
	return ipCountryCount;
}
boost::tuple<map<string,unsigned long>,map<string,unsigned long>,map<string,unsigned long> > KadUtil::GetGeoInfoAndLiveStateFromNodeList(const list<KadNode>& nodeList)
{
	map<string,unsigned long> ipCountryCount;
	map<string,unsigned long> live_ipCountryCount;
	map<string,unsigned long> unmatched_ipCountryCount;

	ContactList::const_iterator it = nodeList.begin();
	for(;it != nodeList.end() && gi != NULL;it++)
	{
		const KadNode& node = *it;
		const char * country_string = GeoIP_country_code_by_addr(gi,inet_ntoa(*((in_addr*)&node.ipNetOrder)));
		if(country_string == NULL)
			continue;

		int country_id = GeoIP_id_by_addr(gi,inet_ntoa(*((in_addr*)&node.ipNetOrder)));
		const char * full_country_string = GeoIP_country_name_by_id(gi,country_id);

		string country_code = full_country_string;
        if(node.state == KAD_ALIVE)
        {
            map<string,unsigned long>::iterator live_it = live_ipCountryCount.find(country_code);
            if(live_it != live_ipCountryCount.end())
            {
                live_it->second++;
            }
            else
                live_ipCountryCount.insert(make_pair(country_code,1));
        }
        else if(node.state == KAD_UNMATCHED)
        {
            map<string,unsigned long>::iterator unmatched_it = unmatched_ipCountryCount.find(country_code);
            if(unmatched_it != unmatched_ipCountryCount.end())
            {
                unmatched_it->second++;
            }
            else
                unmatched_ipCountryCount.insert(make_pair(country_code,1));
            
        }
		map<string,unsigned long>::iterator mapIt = ipCountryCount.find(country_code);
		if(mapIt != ipCountryCount.end())
		{
			mapIt->second++;
		}
		else
		{
			ipCountryCount[country_code]=1;
		}
	}
    //boost::tuple<map<string,unsigned long>,map<string,unsigned long>,map<string,unsigned long> > result(ipCountryCount,live_ipCountryCount,unmatched_ipCountryCount);
    boost::tuple<map<string,unsigned long>,map<string,unsigned long>,map<string,unsigned long> > result(ipCountryCount,live_ipCountryCount,unmatched_ipCountryCount);
	return result;
}
map<string,unsigned long> KadUtil::GetAsInfoFromNodeList(const list<KadNode>& nodeList)
{
	map<string,unsigned long> ipAsCount;

	ContactList::const_iterator it = nodeList.begin();
	for(;it != nodeList.end() && gi != NULL;it++)
	{
		const KadNode& node = *it;
		string as_string = getASNumFromIP(ntohl(node.ipNetOrder));
		map<string,unsigned long>::iterator mapIt = ipAsCount.find(as_string);
		if(mapIt != ipAsCount.end())
		{
			mapIt->second++;
		}
		else
		{
			ipAsCount[as_string]=1;
		}
	}
	return ipAsCount;
}

string KadUtil::getCountryNameFromIP(unsigned long ip)
{
    if(gi == NULL)
        return "WW";
	int country_id = GeoIP_id_by_addr(gi,inet_ntoa(*((in_addr*)&ip)));
	const char * full_country_string = GeoIP_country_name_by_id(gi,country_id);
	if(full_country_string == NULL)
		return string("Unknown place on Mars");
    string country_name = full_country_string;
	return country_name;
}

string KadUtil::getCountryCodeFromIP(unsigned long ip)
{
    if(gi == NULL)
    {
        return "ww";
    }
	const char * country_string = GeoIP_country_code_by_addr(gi,inet_ntoa(*((in_addr*)&ip)));
    if(country_string == NULL)
        return "ZZ";
    string country_code = country_string;
    return country_string;
}
string KadUtil::getASNumFromIP(unsigned long ip)
{
    if(gi_as == NULL)
    {
        return "Unknown AS Num";
    }
    const char* as_num = GeoIP_name_by_ipnum(gi_as,ip);
    if(as_num == NULL)
        return "Unknown AS Num";
    string as_string = as_num;
    return as_string;
}
string KadUtil::getQQIpInfoFromIP(unsigned long ip)
{
    return qqIpEngine->GetIpInfo(ip);
}
string KadUtil::getGeoCityInfoFromIP(unsigned long ip)
{
    if(gi_city == NULL)
    {
        return "Unknown city";
    }
    const char* city = GeoIP_name_by_ipnum(gi_city,ip);
    if(city == NULL)
        return "Unknown city";
    return city;
}

string KadUtil::getFullIpGeoInfoFromIP(unsigned long ip)
{
    std::ostringstream stream;    
    stream<<getCountryNameFromIP(ip);
    stream<<" ";
    stream<<getASNumFromIP(ntohl(ip));
    //stream<<" ";
    //stream<<getGeoCityInfoFromIP(ip);
    stream<<" ";
    stream<<getQQIpInfoFromIP(ntohl(ip));
    return stream.str();
}

bool KadUtil::fromNodeFileToSqlite(string nodeFilePath,string sqlitePath)
{
	list<KadNode> nodeList;
	readKadNodesDataToList(nodeFilePath,nodeList);
	DatabaseLogger db;
	db.init(sqlitePath);
	return db.SaveAllKadNode(nodeList);
}
bool KadUtil::fromNodeFileToCsv(string nodeFilePath,string csvPath)
{
    list<KadNode> nodeList;
    readKadNodesDataToList(nodeFilePath,nodeList);
    writeKadNodesToCSV(nodeList,csvPath);
    return true;
}
string KadUtil::showDuplicateCountDuringSearch()
{
	std::ostringstream stream;
	stream<<endl<<"Duplicate Count in each search iteration: ";
	
	for(unsigned int i=0;i<duplicateCountVector.size();i++)
	{
		stream<<duplicateCountVector[i]<<" ";
	}
	stream<<endl;
	return stream.str();
}
int geoInfoCmp(const std::pair<string,unsigned long>&x,const std::pair<string,unsigned long>&y)
{
	return x.second > y.second;
}
string KadUtil::DumpNodesIPGeoInfo(ContactList nodeList)
{
    boost::tuple<map<string,unsigned long>,map<string,unsigned long>,map<string,unsigned long> > geo_tuple = KadUtil::GetGeoInfoAndLiveStateFromNodeList(nodeList);
    map<string,unsigned long> ipCountryCount = geo_tuple.get<0>();
    map<string,unsigned long> live_ipCountryCount = geo_tuple.get<1>();
    map<string,unsigned long> unmatched_ipCountryCount = geo_tuple.get<2>();
    
	std::ostringstream stream;
	stream<<endl;
	vector<pair<string,unsigned long> > geoInfoPairVector;
	map<string,unsigned long>::iterator itMap = ipCountryCount.begin();
	while(itMap != ipCountryCount.end())
	{
		//stream<<itMap->first<<"  "<<itMap->second<<" "<<((double)itMap->second/(double)nodeList.size())*100<<"%"<<endl;
		geoInfoPairVector.push_back(make_pair(itMap->first,itMap->second));
		itMap++;
	}

	sort(geoInfoPairVector.begin(),geoInfoPairVector.end(),geoInfoCmp);
	stream.precision(2);
	for(unsigned int i=0;i<geoInfoPairVector.size();i++)
	{
		pair<string,unsigned long> geoInfo = geoInfoPairVector[i];
        unsigned long live_count = live_ipCountryCount[geoInfo.first];
        unsigned long unmatched_count = unmatched_ipCountryCount[geoInfo.first];
		stream<<geoInfo.first<<"  "<<geoInfo.second<<" "<<((double)geoInfo.second/(double)nodeList.size())*100<<"%"<<"      "<<live_count<<" "<<(double)live_count/(double)geoInfo.second<<"    "<<unmatched_count<<"   "<<(double)unmatched_count/(double)geoInfo.second<<endl;
	}

	unsigned long count = count_if(nodeList.begin(),nodeList.end(),checkInSame8bitZone(KadUtil::kad_id));
	stream << endl;
	stream <<"Coutries Coverage "<<ipCountryCount.size()<<endl;
	stream <<"The number of nodes which have the same prefix "<<count<<endl;

	return stream.str();
}
string KadUtil::DumpNodesIPAsInfo(ContactList nodeList)
{
	map<string,unsigned long> ipAsCount = KadUtil::GetAsInfoFromNodeList(nodeList);
	std::ostringstream stream;
	stream<<endl;
	vector<pair<string,unsigned long> > asInfoPairVector;
	map<string,unsigned long>::iterator itMap = ipAsCount.begin();
	while(itMap != ipAsCount.end())
	{
		//stream<<itMap->first<<"  "<<itMap->second<<" "<<((double)itMap->second/(double)nodeList.size())*100<<"%"<<endl;
		asInfoPairVector.push_back(make_pair(itMap->first,itMap->second));
		itMap++;
	}

	sort(asInfoPairVector.begin(),asInfoPairVector.end(),geoInfoCmp);
	stream.precision(2);
	for(unsigned int i=0;i<asInfoPairVector.size();i++)
	{
		pair<string,unsigned long> asInfo = asInfoPairVector[i];
		stream<<asInfo.first<<"  "<<asInfo.second<<" "<<((double)asInfo.second/(double)nodeList.size())*100<<"%"<<endl;
	}

	stream << endl;
	stream <<"As Coverage "<<ipAsCount.size()<<endl;

	return stream.str();
}

void KadUtil::writeKadNodesToCSV(const list<KadNode>& nodeList,string savePath)
{
    list<KadNode>::const_iterator it = nodeList.begin();
    
	ofstream fs;
    fs.open(savePath.c_str(),ios_base::out);
    std::ostringstream col_str;
    col_str<<"kad_id,zone_index,ip,coutry_name,country_name,country_code,udp_port,tcp_port,version,udp_key"<<endl;
    fs.write(col_str.str().c_str(),col_str.str().size());
    for(;it!=nodeList.end();it++)
    {
        const KadNode& node = *it;                   
        std::ostringstream stream;
        stream<<"\""<<node.kad_id.ToHexString()<<"\",";
        stream<<((unsigned int)node.kad_id.GetByteChunk(0))<<",";
        stream<<node.ipNetOrder<<",";
        stream<<"\""<<inet_ntoa(*((in_addr*)&node.ipNetOrder))<<"\",";
        string country_name = getCountryNameFromIP(node.ipNetOrder); 
        string country_code = getCountryCodeFromIP(node.ipNetOrder);
        stream<<"\""<<country_name<<"\",";
        stream<<"\""<<country_code<<"\",";
        stream<<node.udp_port<<",";
        stream<<node.tcp_port<<",";
        stream<<((unsigned int)node.version)<<",";
        stream<<"\""<<node.kadUDPkey.GetInt64Value()<<"\"";
        stream<<endl;
        fs.write(stream.str().c_str(),stream.str().size());
        fs.flush();
    }
    fs.flush();
    fs.close();
}
vector<boost::tuple<string,time_t> > KadUtil::getFileListOfDirectoryInternal(string dir_path,string regex_filter,unsigned long maximum_returned,unsigned long minutesLimit)
{
    using namespace boost::posix_time;
    ptime now_time = second_clock::local_time();
    bool timeLimit = true;
    if(minutesLimit == -1)
    {
        timeLimit = false;
    }
 #ifdef BOOST_1_47
	using namespace boost::filesystem2;
#else
	using namespace boost::filesystem;
#endif
    vector<boost::tuple<string,time_t> > matchedFiles;
	typedef std::multimap<std::time_t,string> result_set_t;
	result_set_t result_set;

	const boost::regex kad_filter(regex_filter);
    typedef boost::date_time::c_local_adjustor<ptime> local_adj;
    
	directory_iterator end_itr;
	for(directory_iterator i(dir_path);i!=end_itr;i++)
	{
		if(!is_regular_file(i->status()))
			continue;
		boost::smatch what;
		if(!boost::regex_match(i->leaf(),what,kad_filter))
			continue;
		const path& pf = (*i).path();
        if(timeLimit)
        {
            std::time_t t = boost::filesystem::last_write_time(pf); 
            ptime lwt_time = local_adj::utc_to_local(from_time_t(t));
            ptime check_time = lwt_time + minutes(minutesLimit);
            if(now_time > check_time && minutesLimit != 0)
                continue;
        }
        string pathname = pf.string();
		result_set.insert(result_set_t::value_type(last_write_time(*i),pathname));
    }
    result_set_t::iterator it = result_set.begin();
    unsigned int count = 1;
	for(;it!=result_set.end();it++)
	{
        boost::tuple<string,time_t> matched_file(it->second,it->first);
		matchedFiles.push_back(matched_file);
        count++;
        if(count > maximum_returned)
            break;
	}
    return matchedFiles;
}
vector<boost::tuple<string,time_t> > KadUtil::getFileListOfDirectoryByTimeQuantile(string dir_path,string regex_filter,unsigned long begin_quantile_long,unsigned int end_quantile_long,unsigned long maximum_returned)
{
    double begin_quantile = (double)begin_quantile_long/(double)100;
    double end_quantile = (double)end_quantile_long/(double)100;
 #ifdef BOOST_1_47
	using namespace boost::filesystem2;
#else
	using namespace boost::filesystem;
#endif
    vector<boost::tuple<string,time_t> > matchedFiles;
	typedef std::multimap<std::time_t,string> result_set_t;
	result_set_t result_set;

	const boost::regex kad_filter(regex_filter);
	directory_iterator end_itr;
	for(directory_iterator i(dir_path);i!=end_itr;i++)
	{
		if(!is_regular_file(i->status()))
			continue;
		boost::smatch what;
		if(!boost::regex_match(i->leaf(),what,kad_filter))
			continue;
		const path& pf = (*i).path();
        string pathname = pf.string();
		result_set.insert(result_set_t::value_type(last_write_time(*i),pathname));
    }
    result_set_t::iterator it = result_set.begin();
    unsigned int count = 1;
    unsigned int count_quantile=1;
	for(;it!=result_set.end();it++)
	{
        double current_quantile=(double)count_quantile/(double)result_set.size();
        if(current_quantile > end_quantile || current_quantile < begin_quantile)
        {
            count_quantile++;
            continue;
        }
        count_quantile++;
        boost::tuple<string,time_t> matched_file(it->second,it->first);
		matchedFiles.push_back(matched_file);
        count++;
        if(count > maximum_returned)
            break;
	}
    return matchedFiles;
}

/**
 * @brief get file list of directory filtered by last write time and maximum returned count
 *
 * @Param dir_path directory of current path
 * @Param regex_filter regex filter
 * @Param maximum_returned maximum returned results
 * @Param minutes time elapsed since last write
 *
 * @return list of file paths
 */
vector<string> KadUtil::getFileListOfDirectoryTimeLimited(string dir_path,string regex_filter,unsigned long maximum_returned,unsigned long minutesLimit)
{
    vector<string> files;
    vector<boost::tuple<string,time_t> > foundfiles = getFileListOfDirectoryInternal(dir_path,regex_filter,maximum_returned,minutesLimit);
    for(unsigned int i=0;i<foundfiles.size();i++)
    {
        files.push_back(foundfiles[i].get<0>());
    }
    return files;
}
vector<string> KadUtil::getFileListOfDirectory(string regex_filter,string dir_path,unsigned long maximum_returned)
{
    vector<string> files;
    vector<boost::tuple<string,time_t> > foundfiles = getFileListOfDirectoryInternal(dir_path,regex_filter,maximum_returned);
    for(unsigned int i=0;i<foundfiles.size();i++)
    {
        files.push_back(foundfiles[i].get<0>());
    }
    return files;
}
list<SimpleKadNode> KadUtil::convertToSimpleNode(const list<KadNode>& nodeList)
{
    list<SimpleKadNode> nodes;
    for (list<KadNode>::const_iterator it=nodeList.begin(); it!=nodeList.end() ; it++)
    {
        const KadNode c_node = *it;
        SimpleKadNode node(c_node.kad_id,c_node.udp_port,c_node.ipNetOrder);
        nodes.push_back(node);
    }
    return nodes;
}
list<KadNode> KadUtil::expandToFullKadNode(const list<SimpleKadNode>& nodeList)
{
    list<KadNode> nodes;
    for (list<SimpleKadNode>::const_iterator it=nodeList.begin(); it!=nodeList.end() ; it++)
    {
        const SimpleKadNode c_node = *it;
	    KadNode node(c_node.kad_id,c_node.ipNetOrder,c_node.udp_port,1111,c_node.kad_id,2,0,false);
        nodes.push_back(node);
    }
    return nodes;
}
list<SearchKadNode> KadUtil::convertToSearchKadNode(const list<KadNode>& nodeList)
{
    list<SearchKadNode> nodes;
    for (list<KadNode>::const_iterator it=nodeList.begin(); it!=nodeList.end() ; it++)
    {
        const KadNode c_node = *it;
        SearchKadNode node;
        node.kad_id = c_node.kad_id;
        node.udp_port = c_node.udp_port;
        node.tcp_port = c_node.tcp_port;
        node.ipNetOrder = c_node.ipNetOrder;
        node.full_ip = c_node.ipNetOrder;
        node.version = c_node.version;
        node.parentIpAddr = c_node.parentIpAddr;
        nodes.push_back(node);
    }
    return nodes;
}
unsigned long KadUtil::getNetmaskLongFromOrder(unsigned int netmask_order)
{
    unsigned long net_mask = 0;
    if(netmask_order > 32)
        netmask_order = 32;
    for(unsigned int i=0;i<netmask_order;i++)
    {
        net_mask = net_mask | (1<<(31-i));
    }
    return net_mask;
}
void KadUtil::convertIPWithNetmask(list<KadNode>& nodeList,unsigned int netmask_order)
{
    unsigned long netmask = getNetmaskLongFromOrder(netmask_order);
    for(list<KadNode>::iterator it = nodeList.begin(); it != nodeList.end();it++)
    {
        KadNode & node = *it;
        node.ipNetOrder = htonl(ntohl(node.ipNetOrder) & netmask);
    }
}
void KadUtil::convertIPWithNetmask(list<SearchKadNode>& nodeList,unsigned int netmask_order)
{
    unsigned long netmask = getNetmaskLongFromOrder(netmask_order);
    for(list<SearchKadNode>::iterator it = nodeList.begin(); it != nodeList.end();it++)
    {
        SearchKadNode & node = *it;
        node.ipNetOrder = htonl(ntohl(node.ipNetOrder) & netmask);
    }
}
void KadUtil::saveIPOfNodeListToPath(string prefix,list<SimpleKadNode> nodeList)
{
    std::ostringstream nameStream;
    nameStream<<KadCrawl::KadUtil::log_directory;
#ifdef WIN32
    nameStream<<"\\";
#else
    nameStream<<"/";
#endif
    nameStream<<prefix<<"_";
    nameStream<<getCurrentTimeString();
    nameStream<<".dat";

    string filepath = nameStream.str();
    ofstream fs;
	fs.open(filepath.c_str(),ios_base::binary|ios_base::out);
    if(!fs.good())
    {
        DEBUG_PRINT2("file could not opened %s\n",filepath.c_str());
        return;
    }
    for(list<SimpleKadNode>::iterator it = nodeList.begin();it != nodeList.end();it++)
    {
        SimpleKadNode& node = *it;
        fs.write((char*)&node.ipNetOrder,sizeof(uint32));        
    }
    fs.close();
}
/**
 * @brief randomly pick up groups of nodes from node list
 *
 * @Param nodeList list of nodes from which we randomly pick
 * @Param size the size of nodelist to pick
 *
 * @return randomly picked nodes
 */
list<KadNode> KadUtil::extractRandomSetFromNodeList(list<KadNode> nodeList,unsigned long size) 
{
    if(nodeList.size()==0)
        return nodeList;
    uint32 random_int = cryptRandomGen.GenerateWord32(0,0xFFFFFFFF);
    unsigned long seed = 1931;
    boost::mt19937 rng(time(0));
    boost::uniform_int<> data_dist(1,size);
    unsigned int list_size = nodeList.size();
    list<KadNode> result_list;
    vector<KadNode> node_tmp;
    for(list<KadNode>::iterator it = nodeList.begin();it!=nodeList.end();it++)
    {
        node_tmp.push_back(*it);
    }
    boost::variate_generator<boost::mt19937&, boost::uniform_int<> > randomNumber(rng, data_dist);
    random_shuffle(node_tmp.begin(),node_tmp.end(),randomNumber);
    for(unsigned int i=0;i<size;i++)
    {
        result_list.push_back(node_tmp[i]);    
    }
    return result_list;
}
/**
 * @brief extract all the live kad nodes from the whole node list
 *
 * @Param nodeList list of nodes from which we extract live nodes
 *
 * @return list of live kad nodes
 */
list<KadNode> KadUtil::extractLiveNodesFromNodeList(list<KadNode> nodeList) 
{
    if(nodeList.size()==0)
        return nodeList;
    list<KadNode> result_list;
    for(list<KadNode>::iterator it = nodeList.begin();it!=nodeList.end();it++)
    {
        KadNode& node = *it;
        if(node.state == KAD_ALIVE)
            result_list.push_back(node);
    }
    return result_list;
}
/**
 * @brief extract all the unmatched kad nodes from the whole node list
 *
 * @Param nodeList list of nodes from which we extract live nodes
 *
 * @return list of unmatched kad nodes
 */
list<KadNode> KadUtil::extractUnmatchedNodesFromNodeList(list<KadNode> nodeList) 
{
    if(nodeList.size()==0)
        return nodeList;
    list<KadNode> result_list;
    for(list<KadNode>::iterator it = nodeList.begin();it!=nodeList.end();it++)
    {
        KadNode& node = *it;
        if(node.state == KAD_UNMATCHED)
            result_list.push_back(node);
    }
    return result_list;
}

/**
 * @brief extract all the kad nodes with specified version from the whole node list
 *
 * @Param nodeList list of nodes from which we extract live nodes
 * @Param version version number of which to extract
 *
 * @return list of kad nodes of specified version
 */
list<KadNode> KadUtil::extractNodesFromNodeListByVersion(list<KadNode> nodeList,unsigned short version) 
{
    if(nodeList.size()==0)
        return nodeList;
    list<KadNode> result_list;
    for(list<KadNode>::iterator it = nodeList.begin();it!=nodeList.end();it++)
    {
        KadNode& node = *it;
        if(node.version == version)
            result_list.push_back(node);
    }
    return result_list;
}
list<KadNode> KadUtil::extractNodesOfSpecificCountryFromNodeList(list<KadNode> nodeList,string country_code)
{
    list<KadNode> nodeList_country;
    for(list<KadNode>::iterator it = nodeList.begin();it != nodeList.end();it++)
    {
        KadNode node = *it;
        string country_name = KadCrawl::KadUtil::getCountryNameFromIP(node.ipNetOrder);
        if(country_name == country_code)
            nodeList_country.push_back(node);
    }
    return nodeList_country;
}
bool KadUtil::checkOrBlockFilter(const KadNode& node,const KadFilter& filter)
{
    if(!filter.check_flag)
        return true;
    if(filter.check_zone_id)
    {
        uint8 zone_index = node.kad_id.GetByteChunk(0);
        uint8 zone_index_comp = filter.node.kad_id.GetByteChunk(0);
        if(zone_index == zone_index_comp)
            return false;
    }
    if(filter.check_ip)
    {
        uint32 ip = node.ipNetOrder;
        uint32 ip_comp = filter.node.ipNetOrder;
        if(ip == ip_comp)
            return false;
    }
    if(filter.check_udp_port)
    {
        uint16 port = node.udp_port;
        uint16 port_comp = filter.node.udp_port;
        if(port == port_comp)
            return false;
    }
    if(filter.check_version)
    {
        uint8 version = node.version;
        uint8 version_comp = filter.node.version;
        if(version == version_comp)
            return false;
    }
    if(filter.check_tcp_port)
    {
        uint16 port = node.tcp_port;
        uint16 port_comp = filter.node.tcp_port;
        if(port == port_comp)
            return false;
    }
    if(filter.check_kad_state)
    {
        uint8 state = node.state;
        uint8 state_comp = filter.node.state;
        if(state == state_comp)
            return false;
    }
    return true;
}
// block all the nodes which don't conform to any of the condition specified
// conjunction
bool KadUtil::checkFilter(const KadNode& node,const KadFilter& filter)
{
    if(!filter.check_flag)
        return true;
    if(filter.check_zone_id)
    {
        uint8 zone_index = node.kad_id.GetByteChunk(0);
        uint8 zone_index_comp = filter.node.kad_id.GetByteChunk(0);
        if(zone_index != zone_index_comp)
            return false;
    }
    if(filter.check_ip)
    {
        uint32 ip = node.ipNetOrder;
        uint32 ip_comp = filter.node.ipNetOrder;
        if(ip != ip_comp)
            return false;
    }
    if(filter.check_udp_port)
    {
        uint16 port = node.udp_port;
        uint16 port_comp = filter.node.udp_port;
        if(port != port_comp)
            return false;
    }
    if(filter.check_version)
    {
        uint8 version = node.version;
        uint8 version_comp = filter.node.version;
        if(version != version_comp)
            return false;
    }
    if(filter.check_tcp_port)
    {
        uint16 port = node.tcp_port;
        uint16 port_comp = filter.node.tcp_port;
        if(port != port_comp)
            return false;
    }
    if(filter.check_kad_state)
    {
        uint8 state = node.state;
        uint8 state_comp = filter.node.state;
        if(state != state_comp)
            return false;
    }
    return true;
}
