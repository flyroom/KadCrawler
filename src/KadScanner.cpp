// Kadcanner.cpp: implementation of the KadScanner class.
//
//////////////////////////////////////////////////////////////////////

#include"config.h"
#include"KadUtil.h"
#include"DatabaseLogger.h"
#include"KadScanner.h"
#include"KadAnalyzer.h"

using namespace boost;
using namespace KadCrawl;
using namespace boost::interprocess;

//typedef property<vertex_name_t,KadNode*> VertexProperties;
struct VertexProperties {
  std::size_t index;
  KadNode *node;
};
typedef adjacency_list<listS,vecS,bidirectionalS,VertexProperties> Graph;
typedef graph_traits<Graph> Traits;
typedef Traits::vertex_descriptor Vertex;
typedef Traits::edge_descriptor GraphEdge;
typedef property_map<Graph,KadNode* VertexProperties::*>::type NameMap;
typedef property_traits<NameMap>::value_type nodeValueType;

extern CryptoPP::AutoSeededRandomPool cryptRandomGen;
extern KadAnalyzer kadAnalyzer;

bool nodeCompare(vector<unsigned char> key_A,vector<unsigned char> key_B)
{
    if(key_A.size()!=key_B.size())  
        return false;
    for(unsigned int i=0;i<key_A.size();i++)
    {
        if(key_A[i] != key_B[i])
            return false;
    }
    return true;
}

KadScanner::KadScanner()
{
	routingZone = NULL;
	searchResultType = SEARCH_KEYWORD;
    processImmediatelly = true;
    useHashTable = false;
}
KadScanner::~KadScanner()
{
	Destroy();
}
void KadScanner::Destroy()
{
	if(routingZone != NULL)
	{
		delete routingZone;
		routingZone = NULL;
	}
}
int KadScanner::readKadNodesDataFile(string filepath)
{
	unsigned int version;
	version = KadUtil::readKadNodesDataToList(filepath,nodeList);
	bootstrapNodeList = nodeList;
	sendRequestList.insert(sendRequestList.end(),nodeList.begin(),nodeList.end());
	nodeList.sort();
    if(useHashTable)
    {
        for(list<KadNode>::iterator it=nodeList.begin();it!=nodeList.end();it++)
        {
            KadNode& node = *it;
            putNodeToTempList(node);
        }
    }
	return version;
}
void KadScanner::setAllNodesToInactive()
{
    for(list<KadNode>::iterator it=nodeList.begin();it!=nodeList.end();it++)
    {
        KadNode& node = *it;
        node.verified = true;
    }
    if(!useHashTable)
        return;
    for(HashedNodeMap::iterator it_hash=nodesMap.begin();it_hash!=nodesMap.end();it_hash++)
    {
        KadNode& node = it_hash->second;
        node.verified = true;
    }
}
void KadScanner::setUseHashTable(bool useHashTable)
{
    this->useHashTable = useHashTable;
}
void KadScanner::setToBootstrapNodes()
{
	nodeList = bootstrapNodeList;
	nodeList.sort();
	sendRequestList.clear();
	sendRequestList.insert(sendRequestList.end(),nodeList.begin(),nodeList.end());
}
void KadScanner::setToNearerNodesFromBootNodes(CUInt128 target_id,uint32 range)
{
	nodeList = bootstrapNodeList;
	nodeList.sort();
	nodeList = KadUtil::GetNeighboringNodes(nodeList,target_id,range);
	sendRequestList.clear();
	sendRequestList.insert(sendRequestList.end(),nodeList.begin(),nodeList.end());
}
bool operator>(vector<unsigned char>& key_A,vector<unsigned char>& key_B)
{
    if(key_A.size()!=key_B.size())  
        return false;
    for(unsigned int i=0;i<key_A.size();i++)
    {
        if(key_A[i] != key_B[i])
            return false;
    }
    DEBUG_PRINT1("compare");
    return true;
}
unsigned long KadScanner::GetActiveUnknowNodeSize()
{
    return active_unmatched_node_size;
}

void KadScanner::putKadNodeToAliveState(SimpleKadNode target_node)
{
    if(useHashTable)
    {
        MD5 md5_gen;
        bool flipped_global = false;
        uint8 md5sum[16]={0};
        uint8 md5sum_flipped[16]={0};
        KadNodeStruct sKadNode;
        memset(&sKadNode,0,sizeof(KadNodeStruct));
        uint32* id_data = (uint32*)target_node.kad_id.GetDataPtr();
        sKadNode.id[0] = *id_data;
        sKadNode.id[1] = *(id_data+1);
        sKadNode.id[2] = *(id_data+2);
        sKadNode.id[3] = *(id_data+3);
        sKadNode.udp_port = target_node.udp_port;
        sKadNode.ipNetOrder = target_node.ipNetOrder;

        CUInt128 flipped_id = target_node.kad_id;
        if(flipped_id.GetBitNumber(0))
        {
            flipped_id.SetBitNumber(0,0);
        }
        else
        {
            flipped_id.SetBitNumber(0,1);
        }
        
        KadNodeStruct sKadNodeFlipped;
        memset(&sKadNodeFlipped,0,sizeof(KadNodeStruct));
        id_data = (uint32*)flipped_id.GetDataPtr();
        sKadNodeFlipped.id[0] = *id_data;
        sKadNodeFlipped.id[1] = *(id_data+1);
        sKadNodeFlipped.id[2] = *(id_data+2);
        sKadNodeFlipped.id[3] = *(id_data+3);
        sKadNodeFlipped.udp_port = target_node.udp_port;
        sKadNodeFlipped.ipNetOrder = target_node.ipNetOrder;
        
        /*
        CUInt128 test_id = target_node.kad_id;
        CUInt128 flipped_test_id = test_id;
        if(flipped_test_id.GetBitNumber(0))
        {
            flipped_test_id.SetBitNumber(0,0);
        }
        else
        {
            flipped_test_id.SetBitNumber(0,1);
        }
        
        KadNode matched_node;
        for(HashedNodeMap::iterator it_test = nodesMap.begin();it_test!=nodesMap.end();it_test++)
        {
            KadNode node = it_test->second;
            if(node.kad_id == test_id)
            {
                if(sKadNode.udp_port == node.udp_port && sKadNode.ipNetOrder == node.ipNetOrder)
                {
                    matched_node = node;
                    flipped_global = false;
                    break;
                }
            }
            if(node.kad_id == flipped_test_id)
            {
                if(sKadNode.udp_port == node.udp_port && sKadNode.ipNetOrder == node.ipNetOrder)
                {
                    uint32* id_data_flipped = (uint32*)flipped_test_id.GetDataPtr();
                    sKadNode.id[0] = *id_data_flipped;
                    sKadNode.id[1] = *(id_data_flipped+1);
                    sKadNode.id[2] = *(id_data_flipped+2);
                    sKadNode.id[3] = *(id_data_flipped+3);
                    flipped_global=true;
                    break;
                }
            }
        }
        */
        md5_gen.CalculateDigest(md5sum,(uint8*)&sKadNode,sizeof(KadNodeStruct));
        md5_gen.CalculateDigest(md5sum_flipped,(uint8*)&sKadNodeFlipped,sizeof(KadNodeStruct));
        
        vector<unsigned char> node_key(md5sum,md5sum+sizeof(uint8)*16);
        vector<unsigned char> node_key_flipped(md5sum_flipped,md5sum_flipped+sizeof(uint8)*16);
        
        HashedNodeMap::iterator exist_node_it = nodesMap.find(node_key);
        HashedNodeMap::iterator exist_node_flipped_it = nodesMap.find(node_key_flipped);
        
        CUInt128 matched_id = target_node.kad_id;
        
        if(exist_node_it != nodesMap.end())
        {
            KadNode& node = exist_node_it->second;
            node.state = KAD_ALIVE;
            matched_id = node.kad_id;
        }
        if(exist_node_flipped_it != nodesMap.end())
        {
            KadNode& node = exist_node_flipped_it->second;
            node.state = KAD_ALIVE;
            matched_id = node.kad_id;
        }
        if(exist_node_it != nodesMap.end()&& exist_node_flipped_it != nodesMap.end())
        {
            ostringstream stream;
            stream<<"Both id had been found : exception";
            KadLogger::Log(WARN_KAD_LOG,stream.str());
            DEBUG_PRINT2("%s\n",stream.str().c_str());
        }
        if(exist_node_it == nodesMap.end()&& exist_node_flipped_it == nodesMap.end())
        {
            active_unmatched_node_size++;
            unmatched_live_nodelist.push_back(target_node);
            /*
            for(HashedNodeMap::iterator it_test = nodesMap.begin();it_test!=nodesMap.end();it_test++)
            {
                KadNode node = it_test->second;
                vector<unsigned char> hash = it_test->first;
                bool same_id=false;
                bool same_ip=false;
                bool same_udp=false;
                bool same_hash=false;
                bool flipped=false;
                unsigned int count=0;
                if(node.kad_id == matched_id)
                {
                    same_id = true;
                    count++;
                }
                if(node.ipNetOrder == sKadNode.ipNetOrder)
                {
                    same_ip = true;
                    count++;
                }
                if(node.udp_port == sKadNode.udp_port)
                {
                    same_udp = true;
                    count++;
                }
                if(node_key == hash)
                {
                    same_hash = true;
                }
                if(matched_id != target_node.kad_id)
                {
                    flipped=true;
                }
                if(count>1)
                {
                    ostringstream stream;
                    stream<<"ID: "<<same_id<<" IP: "<<same_ip<<" PORT: "<<same_udp<<" Hash: "<<same_hash<<" Flipped: "<<flipped<<endl;
                    stream<<node.dumpInfo()
                    DEBUG_PRINT2("%s\n",stream.str().c_str());
                }
            }
            */
        }
    }
}
void KadScanner::processUnmatchedNodeList()
{
    HashedNodeMap noPortNodeMap;
    HashKeyConnector connector;
    MD5 md5_gen;
    unsigned long unknown_node_size=0;
    
    for(HashedNodeMap::iterator it_all = nodesMap.begin();it_all != nodesMap.end();it_all++)
    {
        KadNode node = it_all->second;
        uint8 md5sum[16]={0};
        KadNodeWithoutPort sKadNode;
        memset(&sKadNode,0,sizeof(KadNodeWithoutPort));
        uint32* id_data = (uint32*)node.kad_id.GetDataPtr();
        sKadNode.id[0] = *id_data;
        sKadNode.id[1] = *(id_data+1);
        sKadNode.id[2] = *(id_data+2);
        sKadNode.id[3] = *(id_data+3);
        sKadNode.ip = node.ipNetOrder;

        md5_gen.CalculateDigest(md5sum,(uint8*)&sKadNode,sizeof(KadNodeWithoutPort));
        vector<unsigned char> node_key(md5sum,md5sum+sizeof(uint8)*16);
        HashedNodeMap::iterator no_port_it = noPortNodeMap.find(node_key);
        if(no_port_it == noPortNodeMap.end())
        {
            noPortNodeMap.insert(make_pair(node_key,node));
        }
        connector.insert(make_pair(node_key,it_all->first));
    }

    unsigned int connector_size=0;
    for(HashKeyConnector::iterator connector_size_it = connector.begin();connector_size_it != connector.end();connector_size_it++)
    {
        pair<HashKeyConnector::iterator,HashKeyConnector::iterator> connector_size_range=connector.equal_range(connector_size_it->first);
        unsigned int value_count=0;
        for(HashKeyConnector::iterator connector_size_value_it = connector_size_range.first;connector_size_value_it != connector_size_range.second;connector_size_value_it++)
        {
            value_count++;    
        }
        connector_size+=value_count;
    }

    std::ostringstream noPort_stream;    
    noPort_stream<<"connector size: "<<connector.size()<<endl;
    noPort_stream<<"connector value total count: "<<connector_size<<endl;
    noPort_stream<<"unmatched no port nodes map size: "<<noPortNodeMap.size()<<endl;
    noPort_stream<<"nodes map size: "<<nodesMap.size()<<endl;
    DEBUG_PRINT2("%s\n",noPort_stream.str().c_str());
    KadLogger::Log(INFO_KAD_LOG,noPort_stream.str());

    unsigned int unmatched_duplicates_size=0;
    for(list<SimpleKadNode>::iterator it = unmatched_live_nodelist.begin();it!=unmatched_live_nodelist.end();it++)
    {
        SimpleKadNode node = *it;
        KadNodeWithoutPort sKadNode;
        memset(&sKadNode,0,sizeof(KadNodeWithoutPort));
        uint32* id_data = (uint32*)node.kad_id.GetDataPtr();
        sKadNode.id[0] = *id_data;
        sKadNode.id[1] = *(id_data+1);
        sKadNode.id[2] = *(id_data+2);
        sKadNode.id[3] = *(id_data+3);
        sKadNode.ip = node.ipNetOrder;

        CUInt128 flipped_id = node.kad_id;
        if(flipped_id.GetBitNumber(0))
        {
            flipped_id.SetBitNumber(0,0);
        }
        else
        {
            flipped_id.SetBitNumber(0,1);
        }
        KadNodeWithoutPort sKadNode_flipped;
        memset(&sKadNode_flipped,0,sizeof(KadNodeWithoutPort));
        id_data = (uint32*)flipped_id.GetDataPtr();
        sKadNode_flipped.id[0] = *id_data;
        sKadNode_flipped.id[1] = *(id_data+1);
        sKadNode_flipped.id[2] = *(id_data+2);
        sKadNode_flipped.id[3] = *(id_data+3);
        sKadNode_flipped.ip = node.ipNetOrder;

        uint8 md5sum[16]={0};
        uint8 md5sum_flipped[16]={0};
        md5_gen.CalculateDigest(md5sum,(uint8*)&sKadNode,sizeof(KadNodeWithoutPort));
        md5_gen.CalculateDigest(md5sum_flipped,(uint8*)&sKadNode_flipped,sizeof(KadNodeWithoutPort));

        vector<unsigned char> node_key(md5sum,md5sum+sizeof(uint8)*16);
        vector<unsigned char> node_key_flipped(md5sum_flipped,md5sum_flipped+sizeof(uint8)*16);
                
        HashedNodeMap::iterator exist_node_it = noPortNodeMap.find(node_key);
        HashedNodeMap::iterator exist_node_flipped_it = noPortNodeMap.find(node_key_flipped);
        
        bool matched=false;
        bool flipped=false;
        
        if(exist_node_it != noPortNodeMap.end())
        {
            KadNode& node = exist_node_it->second;
            matched=true;
        }
        if(exist_node_flipped_it != noPortNodeMap.end())
        {
            KadNode& node = exist_node_flipped_it->second;
            matched=true;
            flipped=true;
        }
        if(exist_node_it != noPortNodeMap.end()&& exist_node_flipped_it != noPortNodeMap.end())
        {
            ostringstream stream;
            stream<<"Both id had been found : exception";
            KadLogger::Log(WARN_KAD_LOG,stream.str());
            DEBUG_PRINT2("%s\n",stream.str().c_str());
        }
        if(exist_node_it == noPortNodeMap.end()&& exist_node_flipped_it == noPortNodeMap.end())
        {
            unknown_node_size++;                    
        }
        if(matched)    
        {
            KadNode* fix_node;
            vector<unsigned char> fix_key;

            if(flipped)
            {
                fix_node = &exist_node_flipped_it->second;
                fix_key = exist_node_flipped_it->first;
            }
            else
            {
                fix_node = &exist_node_it->second;
                fix_key = exist_node_it->first;
            }
            fix_node->state = KAD_UNMATCHED;
            pair<HashKeyConnector::iterator, HashKeyConnector::iterator> keyRange = connector.equal_range(fix_key);
            HashKeyConnector::iterator connector_it;
            for(connector_it = keyRange.first;connector_it != keyRange.second;connector_it++)
            {
                vector<unsigned char> found_key = connector_it->second;
                HashedNodeMap::iterator fix_nodesMap_it = nodesMap.find(found_key);
                if(fix_nodesMap_it != nodesMap.end())
                {
                    KadNode& node = fix_nodesMap_it->second;
                    if(node.state == KAD_UNMATCHED)
                    {
                        unmatched_duplicates_size++;
                    }
                    node.state = KAD_UNMATCHED;
                }
            }
        }
    }
    std::ostringstream stream;
    stream<<"Remaining unknown nodes size: "<<unknown_node_size<<endl;
    stream<<"Unmatched duplicates nodes size: "<<unmatched_duplicates_size<<endl;
    DEBUG_PRINT2("%s\n",stream.str().c_str());
    KadLogger::Log(INFO_KAD_LOG,stream.str());

    /*
    unsigned int test_count=0;
    for(list<SimpleKadNode>::iterator it = unmatched_live_nodelist.begin();it!=unmatched_live_nodelist.end();it++)
    {
        SimpleKadNode& test_node = *it;
        CUInt128 id = test_node.kad_id;
        CUInt128 flipped_id = test_node.kad_id;
        if(flipped_id.GetBitNumber(0))
        {
            flipped_id.SetBitNumber(0,0);
        }
        else
        {
            flipped_id.SetBitNumber(0,1);
        }
        KadNodeWithoutPort sKadNode_test;
        memset(&sKadNode_test,0,sizeof(KadNodeWithoutPort));
        uint32* id_data = (uint32*)id.GetDataPtr();
        sKadNode_test.id[0] = *id_data;
        sKadNode_test.id[1] = *(id_data+1);
        sKadNode_test.id[2] = *(id_data+2);
        sKadNode_test.id[3] = *(id_data+3);
        sKadNode_test.ip = test_node.ipNetOrder;

        KadNodeWithoutPort sKadNode_test_flipped;
        memset(&sKadNode_test_flipped,0,sizeof(KadNodeWithoutPort));
        id_data = (uint32*)flipped_id.GetDataPtr();
        sKadNode_test_flipped.id[0] = *id_data;
        sKadNode_test_flipped.id[1] = *(id_data+1);
        sKadNode_test_flipped.id[2] = *(id_data+2);
        sKadNode_test_flipped.id[3] = *(id_data+3);
        sKadNode_test_flipped.ip = test_node.ipNetOrder;

        uint8 md5sum[16]={0};
        uint8 md5sum_flipped[16]={0};
        md5_gen.CalculateDigest(md5sum,(uint8*)&sKadNode_test,sizeof(KadNodeWithoutPort));
        md5_gen.CalculateDigest(md5sum_flipped,(uint8*)&sKadNode_test_flipped,sizeof(KadNodeWithoutPort));
        
        for(HashedNodeMap::iterator it_test = nodesMap.begin();it_test != nodesMap.end();it_test++)
        {
            KadNode& node = it_test->second;
            vector<unsigned char> hash = it_test->first;
            bool same_id=false;
            bool same_ip=false;
            bool same_udp=false;
            bool same_hash=false;
            bool flipped=false;
            unsigned int count=0;
            if(node.kad_id == id)
            {
                same_id = true;
                count++;
            }
            if(node.ipNetOrder == test_node.ipNetOrder)
            {
                same_ip = true;
                count++;
            }
            if(node.udp_port == test_node.udp_port)
            {
                same_udp = true;
                count++;
            }
            if(node.kad_id == flipped_id)
            {
                flipped=true;
                same_id=true;
                count++;
            }
            if(count>1)
            {
                ostringstream stream;
                stream<<"ID: "<<same_id<<" IP: "<<same_ip<<" PORT: "<<same_udp<<" Flipped: "<<flipped<<endl;
                stream<<node.dumpInfo();
                //DEBUG_PRINT2("%s\n",stream.str().c_str());
                KadLogger::Log(INFO_KAD_LOG,stream.str());
                test_count++;
            }
        }
        if(test_count>50)
            break;
    }
    */
}
list<KadNode> KadScanner::processPingAliveNodes()
{
    HashedNodeMap noIDNodeMap;
    HashKeyConnector connector;
    MD5 md5_gen;
    for(HashedNodeMap::iterator it_all = nodesMap.begin();it_all != nodesMap.end();it_all++)
    {
        KadNode node = it_all->second;
        uint8 md5sum[16]={0};
        KadNodeWithoutID sKadNode;
        memset(&sKadNode,0,sizeof(KadNodeWithoutID));
        sKadNode.ip = node.ipNetOrder;
        sKadNode.udp_port = node.udp_port;

        md5_gen.CalculateDigest(md5sum,(uint8*)&sKadNode,sizeof(KadNodeWithoutID));
        vector<unsigned char> node_key(md5sum,md5sum+sizeof(uint8)*16);
        HashedNodeMap::iterator no_id_it = noIDNodeMap.find(node_key);
        if(no_id_it == noIDNodeMap.end())
        {
            noIDNodeMap.insert(make_pair(node_key,node));
        }
        connector.insert(make_pair(node_key,it_all->first));
    }

    unsigned long unmatched_live_count=0;
    list<KadNode> pingAliveNodeList;
    list<SimpleKadNode>::iterator it_temp = tempKadNodeList.begin();
    for(;it_temp != tempKadNodeList.end();it_temp++)    
    {
        SimpleKadNode& node = *it_temp;
        KadNodeWithoutID sKadNode;
        memset(&sKadNode,0,sizeof(KadNodeWithoutID));
        sKadNode.ip = node.ipNetOrder;
        sKadNode.udp_port = node.udp_port;

        uint8 md5sum[16]={0};
        md5_gen.CalculateDigest(md5sum,(uint8*)&sKadNode,sizeof(KadNodeWithoutID));
        vector<unsigned char> node_key(md5sum,md5sum+sizeof(uint8)*16);
        HashedNodeMap::iterator no_id_it = noIDNodeMap.find(node_key);
        if(no_id_it != noIDNodeMap.end())
        {
            pingAliveNodeList.push_back(no_id_it->second);
        }
        else
            unmatched_live_count++;            
        
    }
    std::ostringstream stream;
    stream<<"unmatched ping alive nodes size: "<<unmatched_live_count<<endl;
    stream<<"matched ping alive nodes size: "<<pingAliveNodeList.size();
    DEBUG_PRINT2("%s\n",stream.str().c_str());
    KadLogger::Log(INFO_KAD_LOG,stream.str());
    return pingAliveNodeList;
}
void KadScanner::setStateOfLiveNodes()
{
    HashedNodeMap::iterator it_hash = nodesMap.begin();
    while(it_hash != nodesMap.end())
    {
        KadNode& node = it_hash->second;
        node.state = KAD_DEAD;
        it_hash++;
    }
    const list<SimpleKadNode> activeList = GetBootstrapRespondingKadNodeList();
    list<SimpleKadNode>::const_iterator it = respondingNodeList.begin();   
    KadCrawl::KadUtil::removeDuplicates(nodeList);
    while(it != respondingNodeList.end())
    {
        const SimpleKadNode& node = *it;
        putKadNodeToAliveState(node);    
        it++;
    }
    HashedNodeMap::iterator it_test = nodesMap.begin();
    while(it_test != nodesMap.end())
    {
        KadNode& node = it_test->second;
        if(node.verified == true)
        {
            node.verified = true;
        }
        it_test++;
    }
    processUnmatchedNodeList();
}
void KadScanner::putNodeToTempList(KadNode target_node)
{
    if(!useHashTable)
        discoveredNodeList.push_back(target_node);
    else
    {
        /*
        MD5 hash;
        uint8 digest[16];
        std::string message = "abcdefghijklmnopqrstuvwxyz";
        hash.CalculateDigest(digest,(uint8*)message.c_str(), message.length() );
        */
        MD5 md5_gen;
        uint8 md5sum[16]={0};
        KadNodeStruct sKadNode;
        memset(&sKadNode,0,sizeof(KadNodeStruct));
        uint32* id_data = (uint32*)target_node.kad_id.GetDataPtr();
        sKadNode.id[0] = *id_data;
        sKadNode.id[1] = *(id_data+1);
        sKadNode.id[2] = *(id_data+2);
        sKadNode.id[3] = *(id_data+3);
        sKadNode.udp_port = target_node.udp_port;
        sKadNode.ipNetOrder = target_node.ipNetOrder;
        //md5_gen.Update((unsigned char*)&sKadNode,sizeof(KadNodeStruct));
        //md5_gen.Final(md5sum);
        md5_gen.CalculateDigest(md5sum,(uint8*)&sKadNode,sizeof(sKadNode));
        vector<unsigned char> node_key(md5sum,md5sum+sizeof(uint8)*16);
        HashedNodeMap::iterator exist_node_it = nodesMap.find(node_key);
        target_node.verified = false;
        if(exist_node_it == nodesMap.end())
        {
            target_node.count = 1;
            nodesMap.insert(std::pair<vector<unsigned char>,KadNode>(node_key,target_node));
        }
        else
        {
            KadNode& node = exist_node_it->second;    
            node.count++;
        }
    }
}
typedef std::pair<vector<unsigned char>,KadNode> HashAndKadNodePair;
typedef vector<HashAndKadNodePair> TestMapVector;
bool compareByKadNode(HashAndKadNodePair pairA,HashAndKadNodePair pairB)
{
    return pairA.second < pairB.second;
}
inline bool eq_kadnode_pip(const HashAndKadNodePair& A,const HashAndKadNodePair& B)
{
    KadNode nodeA = A.second;
    KadNode nodeB = B.second;
	return (nodeA.kad_id==nodeB.kad_id && nodeA.ipNetOrder==nodeB.ipNetOrder && nodeA.udp_port==nodeB.udp_port && nodeA.parentIpAddr==nodeB.parentIpAddr);
}
void KadScanner::checkDuplicateMapItems(HashedNodeMap& map)
{
    HashedNodeMap::iterator it = map.begin();        
    TestMapVector testVector;
    while(it != map.end())
    {
        testVector.push_back(make_pair(it->first,it->second));
        it++;
    }
    sort(testVector.begin(),testVector.end(),compareByKadNode);    
    HashAndKadNodePair comp = testVector[0];
    bool find_duplicate_by_vector=false;
    for(unsigned int i=1;i<testVector.size();i++)
    {
        HashAndKadNodePair cur = testVector[i];
        KadNode kA = cur.second;
        KadNode kB = comp.second;
        if(kA.kad_id==kB.kad_id && kA.udp_port==kB.udp_port && kA.ipNetOrder == kB.ipNetOrder)
        {
            ostringstream stream;
            if(cur.first == comp.first)
            {
                stream<<"duplicates with the same keys";
                KadLogger::Log(FATAL_KAD_LOG,stream.str());
            }
            else
            {
                stream<<"duplicates with different keys "<<endl;
                for(unsigned int i=0;i<cur.first.size();i++)
                {
                    stream<<(unsigned long)cur.first[i]<<" ";
                }
                stream<<endl;
                for(unsigned int i=0;i<comp.first.size();i++)
                {
                    stream<<(unsigned long)comp.first[i]<<" ";
                }
                stream<<endl;
                stream<<kA.kad_id.ToHexString()<<endl;
                stream<<kB.kad_id.ToHexString()<<endl;
                stream<<kA.udp_port<<":"<<kB.udp_port<<" "<<kA.ipNetOrder<<":"<<kB.ipNetOrder<<endl;
                KadLogger::Log(FATAL_KAD_LOG,stream.str());
            }
        }
        comp = cur;
    }
    TestMapVector::iterator it_test_unique = unique(testVector.begin(),testVector.end(),eq_kadnode_pip);
    if(it_test_unique != testVector.end())
    {
        KadNode node = it_test_unique->second;
        unsigned int index = it_test_unique-testVector.begin();
        for(unsigned int j=0;j<index-1;j++)
        {
            if(testVector[j].second == node)
            {
                KadLogger::Log(INFO_KAD_LOG,"Found Duplicates");
                ostringstream stream;
                stream<<node.dumpInfo()<<endl;
                stream<<testVector[j].second.dumpInfo()<<endl;
            }
        }
    }
}
void KadScanner::clearList()
{
	nodeList.clear();
	bootstrapNodeList.clear();
	sendRequestList.clear();
}
string KadScanner::DumpNodesIPGeoInfo()
{
	return KadUtil::DumpNodesIPGeoInfo(nodeList);
}
string KadScanner::DumpNodesInfo()
{
	return KadUtil::DumpNodesInfo(nodeList);
}
int KadScanner::EncryptSendMsg(uchar **ppbyBuf, int nBufLen, const char *pachClientHashOrKadID, bool bKad, uint32 nReceiverVerifyKey, uint32 nSenderVerifyKey)
{
	const uint32 nCryptHeaderLen = CRYPT_HEADER_WITHOUTPADDING+(bKad?8:0);
	uint32 nCryptedLen = nBufLen + nCryptHeaderLen;
	uchar* pachCryptedBuffer = new uchar[nCryptedLen];
	
	uint16 nRandomKeyPart = (uint16)cryptRandomGen.GenerateWord32(0x0000,0xFFFF);

	uint8 byPadLen = 0;

	bool bKadRecKeyUsed = false;
	uchar md5sum[16]={0};

	MD5 md5;
	
	if(bKad)
	{
		if ((pachClientHashOrKadID == NULL || isnulmd4(pachClientHashOrKadID)) && nReceiverVerifyKey != 0) {
			bKadRecKeyUsed = true;
			uchar achKeyData[6];
			PokeUInt32(achKeyData, nReceiverVerifyKey);
			PokeUInt16(achKeyData+4, nRandomKeyPart);

			md5.Update(achKeyData,sizeof(achKeyData));
			md5.Final(md5sum);
			//md5.Calculate(achKeyData, sizeof(achKeyData));
			//DEBUG_ONLY( DebugLog(_T("Creating obfuscated Kad packet encrypted by ReceiverKey (%u)"), nReceiverVerifyKey) );  
		}
		else if (pachClientHashOrKadID != NULL && !isnulmd4(pachClientHashOrKadID)) {
			uchar achKeyData[18];
			md4cpy(achKeyData, pachClientHashOrKadID);
			PokeUInt16(achKeyData+16, nRandomKeyPart);

			md5.Update(achKeyData,sizeof(achKeyData));
			md5.Final(md5sum);
			//md5.Calculate(achKeyData, sizeof(achKeyData));
			//DEBUG_ONLY( DebugLog(_T("Creating obfuscated Kad packet encrypted by Hash/NodeID %s"), md4str(pachClientHashOrKadID)) );  
		}
		else {
			
			delete[] pachCryptedBuffer;
			return nBufLen;
		}
	}

	RC4_Key_Struct keySendKey;
	RC4CreateKey(md5sum, 16, &keySendKey, true);

	uint8 bySemiRandomNotProtocolMarker = 0;
	int i;
	for (i = 0; i < 128; i++){
		bySemiRandomNotProtocolMarker = cryptRandomGen.GenerateByte();
		bySemiRandomNotProtocolMarker = bKad ? (bySemiRandomNotProtocolMarker & 0xFE) : (bySemiRandomNotProtocolMarker | 0x01); // set the ed2k/kad marker bit
		if (bKad)
			bySemiRandomNotProtocolMarker = bKadRecKeyUsed ? ((bySemiRandomNotProtocolMarker & 0xFE) | 0x02) : (bySemiRandomNotProtocolMarker & 0xFC); // set the ed2k/kad and nodeid/reckey markerbit
		else
			bySemiRandomNotProtocolMarker = (bySemiRandomNotProtocolMarker | 0x01); // set the ed2k/kad marker bit
		
		bool bOk = false;
		switch (bySemiRandomNotProtocolMarker){ // not allowed values
		case OP_EMULEPROT:
		case OP_KADEMLIAPACKEDPROT:
		case OP_KADEMLIAHEADER:
		case OP_UDPRESERVEDPROT1:
		case OP_UDPRESERVEDPROT2:
		case OP_PACKEDPROT:
			break;
		default:
			bOk = true;
		}
		if (bOk)
			break;
	}

	if (i >= 128){
		// either we have _really_ bad luck or the randomgenerator is a bit messed up
		bySemiRandomNotProtocolMarker = 0x01;
	}

	uint32 dwMagicValue = MAGICVALUE_UDP_SYNC_CLIENT;
	pachCryptedBuffer[0] = bySemiRandomNotProtocolMarker;
	memcpy(pachCryptedBuffer + 1, &nRandomKeyPart, 2);
	RC4Crypt((uchar*)&dwMagicValue, pachCryptedBuffer + 3, 4, &keySendKey);
	RC4Crypt((uchar*)&byPadLen, pachCryptedBuffer + 7, 1, &keySendKey);

	for (int j = 0; j < byPadLen; j++){
		uint8 byRand = (uint8)rand();	// they actually dont really need to be random, but it doesn't hurts either
		RC4Crypt((uchar*)&byRand, pachCryptedBuffer + CRYPT_HEADER_WITHOUTPADDING + j, 1, &keySendKey);
	}
	
	if (bKad){
		RC4Crypt((uchar*)&nReceiverVerifyKey, pachCryptedBuffer + CRYPT_HEADER_WITHOUTPADDING + byPadLen, 4, &keySendKey);
		RC4Crypt((uchar*)&nSenderVerifyKey, pachCryptedBuffer + CRYPT_HEADER_WITHOUTPADDING + byPadLen + 4, 4, &keySendKey);
	}

	RC4Crypt(*ppbyBuf, pachCryptedBuffer + nCryptHeaderLen, nBufLen, &keySendKey);
	delete[] *ppbyBuf;
	*ppbyBuf = pachCryptedBuffer;

	return nCryptedLen;
}

int KadScanner::DecryptReceivedClient(BYTE *pbyBufIn, int nBufLen, BYTE **ppbyBufOut, uint32 dwIP, uint32 *nReceiverVerifyKey, uint32 *nSenderVerifyKey)
{
	int nResult = nBufLen;
	*ppbyBufOut = pbyBufIn;
	
	if (nReceiverVerifyKey == NULL || nSenderVerifyKey == NULL){
		return nResult;
	}
	
	*nReceiverVerifyKey = 0;
	*nSenderVerifyKey = 0;

	if (nResult <= CRYPT_HEADER_WITHOUTPADDING)
		return nResult;	

	switch (pbyBufIn[0]){
		case OP_EMULEPROT:
		case OP_KADEMLIAPACKEDPROT:
		case OP_KADEMLIAHEADER:
		case OP_UDPRESERVEDPROT1:
		case OP_UDPRESERVEDPROT2:
		case OP_PACKEDPROT:
			return nResult;
	}

	RC4_Key_Struct keyReceiveKey;
	uint32 dwValue = 0;
	// check the marker bit which type this packet could be and which key to test first, this is only an indicator since old clients have it set random
	// see the header for marker bits explanation
	byte byCurrentTry = ((pbyBufIn[0] & 0x03) == 3) ? 1 : (pbyBufIn[0] & 0x03); 
	byte byTries;
	
	byTries = 3;
	bool bKadRecvKeyUsed = false;
	bool bKad = false;
	
	uchar md5sum[16]={0};
	do{
		byTries--;
		MD5 md5;
		
		if (byCurrentTry == 0) {
			// kad packet with NodeID as key
			bKad = true;
			bKadRecvKeyUsed = false;
			
			uchar achKeyData[18];
			memcpy(achKeyData, KadUtil::kad_id.GetData(), 16);
			memcpy(achKeyData + 16, pbyBufIn + 1, 2); // random key part sent from remote client
			md5.Update(achKeyData,sizeof(achKeyData));
		}
		else if (byCurrentTry == 1) {
			// ed2k packet
			/*
			bKad = false;
			bKadRecvKeyUsed = false;
			uchar achKeyData[23];
			md4cpy(achKeyData, thePrefs.GetUserHash());
			achKeyData[20] = MAGICVALUE_UDP;
			memcpy(achKeyData + 16, &dwIP, 4);
			memcpy(achKeyData + 21, pbyBufIn + 1, 2); // random key part sent from remote client
			md5.Update(achKeyData,sizeof(achKeyData));
			*/
		}
		else if (byCurrentTry == 2) {
			// kad packet with ReceiverKey as key
			bKad = true;
			bKadRecvKeyUsed = true;
			
			uchar achKeyData[6];
			PokeUInt32(achKeyData, GetUDPVerifyKey(dwIP));
			memcpy(achKeyData + 4, pbyBufIn + 1, 2); // random key part sent from remote client
			md5.Update(achKeyData,sizeof(achKeyData));
			
		}
		else
			assert( false );
		md5.Final(md5sum);
		RC4CreateKey(md5sum, 16, &keyReceiveKey, true);
		RC4Crypt(pbyBufIn + 3, (uchar*)&dwValue, sizeof(dwValue), &keyReceiveKey);
		byCurrentTry = (byCurrentTry + 1) % 3;
	} while (dwValue != MAGICVALUE_UDP_SYNC_CLIENT && byTries > 0); // try to decrypt as ed2k as well as kad packet if needed (max 3 rounds)
	
	if (dwValue == MAGICVALUE_UDP_SYNC_CLIENT){
		
		if (bKad && (pbyBufIn[0] & 0x01) != 0)
			DEBUG_PRINT2("Received obfuscated UDP packet from clientIP: %s with wrong key marker bits (kad packet, ed2k bit)", ipstr(dwIP).c_str());
		else if (bKad && !bKadRecvKeyUsed && (pbyBufIn[0] & 0x02) != 0)
			DEBUG_PRINT2("Received obfuscated UDP packet from clientIP: %s with wrong key marker bits (kad packet, nodeid key, recvkey bit)", ipstr(dwIP).c_str());
		else if (bKad && bKadRecvKeyUsed && (pbyBufIn[0] & 0x02) == 0)
			DEBUG_PRINT2("Received obfuscated UDP packet from clientIP: %s with wrong key marker bits (kad packet, recvkey key, nodeid bit)", ipstr(dwIP).c_str());

		uint8 byPadLen;
		RC4Crypt(pbyBufIn + 7, (uchar*)&byPadLen, 1, &keyReceiveKey);
		nResult -= CRYPT_HEADER_WITHOUTPADDING;
		if (nResult <= byPadLen){
			DEBUG_PRINT3("Invalid obfuscated UDP packet from clientIP: %s, Paddingsize (%u) larger than received bytes", ipstr(dwIP).c_str(), byPadLen);
			return nBufLen; // pass through, let the Receivefunction do the errorhandling on this junk
		}
		if (byPadLen > 0)
			RC4Crypt(NULL, NULL, byPadLen, &keyReceiveKey);
		nResult -= byPadLen;

		if (bKad){
			if (nResult <= 8){
				DEBUG_PRINT2("Obfuscated Kad packet with mismatching size (verify keys missing) received from clientIP:%s", ipstr(dwIP).c_str());
				return nBufLen;
			}
			
			RC4Crypt(pbyBufIn + CRYPT_HEADER_WITHOUTPADDING + byPadLen, (uchar*)nReceiverVerifyKey, 4, &keyReceiveKey);
			RC4Crypt(pbyBufIn + CRYPT_HEADER_WITHOUTPADDING + byPadLen + 4, (uchar*)nSenderVerifyKey, 4, &keyReceiveKey);
			nResult -= 8;
		}
		*ppbyBufOut = pbyBufIn + (nBufLen - nResult);
		RC4Crypt((uchar*)*ppbyBufOut, (uchar*)*ppbyBufOut, nResult, &keyReceiveKey);
				
		return nResult; 
	}
	else{
		return nBufLen; 
	}
}

bool KadScanner::Init()
{
	KadUtil::Init();
	routingZone = new RoutingZone();
    interactive=false;
    active_unmatched_node_size = 0;
    query_sent_count = 0;

    try
    {
        shared_memory_object::remove("kad_shared_memory");
        shared_memory_object shm(create_only,
                                 "kad_shared_memory",
                                 read_write
                                );
        shm.truncate(sizeof(shared_memory_buffer));
        mapped_region region(shm,
                             read_write);
        void* addr = region.get_address();
        shared_memory_buffer *data = new (addr) shared_memory_buffer;

    }
    catch(interprocess_exception &ex)
    {
        shared_memory_object::remove("kad_shared_memory");
        std::ostringstream stream;
        stream<<"Exception while creating memory object: "<<ex.what();
        DEBUG_PRINT2("%s\n",stream.str().c_str());
        KadLogger::Log(FATAL_KAD_LOG,stream.str());
    }
	return true;
}

uint32 KadScanner::GetUDPVerifyKey(uint32 dwTargetIP)
{
	uint64 ui64Buffer = KadUtil::udpVerifyKey;
	ui64Buffer <<= 32;
	ui64Buffer |= dwTargetIP;
	MD5 md5;
	md5.Update((uchar*)&ui64Buffer,8);
	unsigned char digest[16]={0};
	md5.Final(digest);
	return ((uint32)(PeekUInt32(digest)^PeekUInt32(digest+4)^PeekUInt32(digest+8)^PeekUInt32(digest+12))%0xFFFFFFFF)+1;
}

void KadScanner::sendPacket(uchar *pBuf,uint32 dataLen,uint32 uDestinationHost,uint16 uDestinationPort,KadUDPKey targetUDPKey, const CUInt128 *uCryptTargetID)
{
	if(dataLen < 2)
		return;
	Packet* pPacket = new Packet(OP_KADEMLIAHEADER);
	pPacket->opcode = pBuf[1];
	pPacket->pBuffer = new char[dataLen+8];
	memcpy(pPacket->pBuffer,pBuf+2,dataLen-2);
	pPacket->size = dataLen-2;
	if(dataLen > 200)
		pPacket->PackPacket();
	sendPacket(pPacket,uDestinationHost,uDestinationPort,targetUDPKey,uCryptTargetID);
}

void KadScanner::sendPacket(uchar *pBuf, uint32 dataLen,byte byOpcode, uint32 uDestinationHost, uint16 uDestinationPort, KadUDPKey targetUDPKey, const CUInt128 *uCryptTargetID)
{
	Packet* pPacket = new Packet((char*)pBuf,dataLen,OP_KADEMLIAHEADER);
	pPacket->opcode = byOpcode;
	if(pPacket->size > 200)
		pPacket->PackPacket();

	sendPacket(pPacket,uDestinationHost,uDestinationPort,targetUDPKey,uCryptTargetID);
}

void KadScanner::sendPacket(Packet* pPacket, uint32 uDestinationHost, uint16 uDestinationPort, KadUDPKey targetUDPKey, const CUInt128 *uCryptTargetID)
{
    query_sent_count++;
    
	uint16 nLen = (uint16)pPacket->size+2;
	uchar* sendBuffer = new uchar[nLen];
	memcpy(sendBuffer,pPacket->GetUDPHeader(),2);
	memcpy(sendBuffer+2,pPacket->pBuffer,pPacket->size);

	delete pPacket;

    if(targetUDPKey.GetKeyValue(0) != 0 || uCryptTargetID != NULL )
	    nLen = EncryptSendMsg(&sendBuffer,nLen,(char*)uCryptTargetID->GetData(),true,targetUDPKey.GetKeyValue(0),GetUDPVerifyKey(uDestinationHost));
	
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = uDestinationPort;
#ifdef WIN32
	addr.sin_addr.S_un.S_addr = uDestinationHost;
#else
	addr.sin_addr.s_addr = uDestinationHost;
#endif
#ifdef USE_BOOST_ASIO
	asioServer->send_to(addr,nLen,sendBuffer);
#endif
}

list<KadNode> KadScanner::GetUnRequestedNodeList()
{
	return sendRequestList;
}
const list<KadNode>& KadScanner::GetNodeList()
{
    return nodeList;
}
const HashedNodeMap& KadScanner::GetNodesMap()
{
    return nodesMap;
}
const list<KadNode>& KadScanner::GetCrawledSnapShot()
{
    if(!useHashTable)
    {
	    return nodeList;
    }
    else
    {
        list<KadNode>& local_nodeList = nodeList;
        local_nodeList.clear();
        local_nodeList.insert(local_nodeList.end(),bootstrapNodeList.begin(),bootstrapNodeList.end());
        list<KadNode> nonbootstrapNodes = GetNonBootstrapNodes();
        for(list<KadNode>::iterator it = nonbootstrapNodes.begin();it!=nonbootstrapNodes.end();it++)
        {
            KadNode node = *it;
            if(node.state==KAD_DEAD)
            {
                node.state = KAD_DEAD;
            }
            else
                node.state = KAD_DEAD;
        }
        local_nodeList.insert(local_nodeList.end(),nonbootstrapNodes.begin(),nonbootstrapNodes.end());
        local_nodeList.sort();
        return local_nodeList;
    }
}
void KadScanner::Calibrate()
{
    checkDuplicateMapItems(nodesMap);
    setStateOfLiveNodes();
}
list<KadNode> KadScanner::GetNonBootstrapNodes()
{
    list<KadNode> differenceSet;
    if(!useHashTable)
    {
        list<KadNode> tempList = nodeList;
        set_difference(tempList.begin(),tempList.end(),bootstrapNodeList.begin(),bootstrapNodeList.end(),inserter(differenceSet,differenceSet.begin()));
    }
    else
    {
        HashedNodeMap::iterator it = nodesMap.begin();    
        while(it != nodesMap.end())
        {
            KadNode& node = it->second;
            list<KadNode>::iterator boot_it = find(bootstrapNodeList.begin(),bootstrapNodeList.end(),node);
            if(boot_it == bootstrapNodeList.end())
            {
                differenceSet.push_back(node);
            }
            it++;
        }
    }
	return differenceSet;
}
void KadScanner::setProcessImmediatelly(bool isImmediate)
{
    processImmediatelly = isImmediate;
}
void KadScanner::bufferIncomingPackets(sockaddr_in &address,uint16 count,uint8 *data)
{
   if(count > LARGE_PACKET_LEN)
   {
        std::ostringstream stream;
        stream<<"Abnormal Packet: packet length larger than "<<LARGE_PACKET_LEN;
       	uint32 addrULong=0;
        unsigned short portUShort;
        portUShort = address.sin_port;
#ifdef WIN32
    	addrULong = address.sin_addr.S_un.S_addr;
#else
    	addrULong = address.sin_addr.s_addr;
#endif
        stream<<"  from node with ip "<<inet_ntoa(*((in_addr*)&addrULong))<<" :"<<portUShort;
        stream<<"  "<<KadCrawl::KadUtil::getFullIpGeoInfoFromIP(addrULong);
        KadLogger::Log(INFO_KAD_LOG,stream.str());
		return;
   }
   else if(count > SMALL_PACKET_LEN)
   {
        large_packet packet;     
        packet.len = count;
        memset(packet.content,0,sizeof(unsigned char)*LARGE_PACKET_LEN);
        memcpy(packet.content,data,SMALL_PACKET_LEN);
        unsigned long addrULong;
        unsigned short portUShort;
        portUShort = address.sin_port;
#ifdef WIN32
	addrULong = address.sin_addr.S_un.S_addr;
#else
	addrULong = address.sin_addr.s_addr;
#endif
        packet.source_ip = addrULong;
        packet.source_port = portUShort;
        boost::mutex::scoped_lock lock(processImmediatellyLock);
        bufferedLargePacketList.push_back(packet);
   }
   else
   {
        small_packet packet;
        packet.len = count;
        memset(packet.content,0,sizeof(unsigned char)*SMALL_PACKET_LEN);
        memcpy(packet.content,data,SMALL_PACKET_LEN);
        unsigned long addrULong;
        unsigned short portUShort;
        portUShort = address.sin_port;
#ifdef WIN32
	addrULong = address.sin_addr.S_un.S_addr;
#else
	addrULong = address.sin_addr.s_addr;
#endif
        packet.source_ip = addrULong;
        packet.source_port = portUShort;
        boost::mutex::scoped_lock lock(processImmediatellyLock);
        bufferedPacketList.push_back(packet);
   }
}
void KadScanner::processPacketImmediatelly(sockaddr_in &address,uint16 count,uint8 *data)
{
	BYTE* pBuffer;
	uint32 nReceiverVerifyKey;
	uint32 nSenderVerifyKey;
	uint32 addrULong=0;
#ifdef WIN32
	addrULong = address.sin_addr.S_un.S_addr;
#else
	addrULong = address.sin_addr.s_addr;
#endif
	int nPacketLen = DecryptReceivedClient(data,count,&pBuffer,addrULong,&nReceiverVerifyKey,&nSenderVerifyKey);

	if(nPacketLen >= 1)
	{
		switch(pBuffer[0])
		{
		case OP_EMULEPROT:
			break;
		case OP_KADEMLIAHEADER:
#ifdef WIN32
			addrULong = address.sin_addr.S_un.S_addr;
#else
			addrULong = address.sin_addr.s_addr;
#endif
			processOriginalPacket(pBuffer,
				nPacketLen,
				addrULong,
				address.sin_port,
				GetUDPVerifyKey(addrULong)==nReceiverVerifyKey,
				KadUDPKey(nSenderVerifyKey,0)
				);
			break;
		case OP_KADEMLIAPACKEDPROT:
			processKadPackedPacket(pBuffer,nPacketLen,nReceiverVerifyKey,nSenderVerifyKey,addrULong,address.sin_port);
			break;
		}
	}
}
list<small_packet> KadScanner::ExtractBufferedPacketList()
{
   boost::mutex::scoped_lock lock(processImmediatellyLock);
   DEBUG_PRINT2("Current Size of Buffered Packet List %u\n",bufferedPacketList.size());
   list<small_packet> bufferList=bufferedPacketList;
   bufferedPacketList.clear();
   return bufferList;
}
list<large_packet> KadScanner::ExtractBufferedLargePacketList()
{
   boost::mutex::scoped_lock lock(processImmediatellyLock);
   list<large_packet> bufferList=bufferedLargePacketList;
   bufferedLargePacketList.clear();
   return bufferList;
}
void KadScanner::processPacket(sockaddr_in &address, uint16 count, uint8 *data)
{
    if(!processImmediatelly)
    {  
        bufferIncomingPackets(address,count,data);
    }
    else
    {
        processPacketImmediatelly(address,count,data);
    }
}

void KadScanner::processKadPackedPacket(BYTE *pBuffer, int nPacketLen, uint32 nReceiverVerifyKey, uint32 nSenderVerifyKey,uint32 addrULong,uint16 port)
{

	if(nPacketLen >= 2)
	{
		uint32 nNewSize = nPacketLen*10+300;
		BYTE* unpack = NULL;
		int iZLibResult = 0;
		ULONG unpackedsize=0;
		do{
			delete[] unpack;
			unpack = new BYTE[nNewSize];
			unpackedsize = nNewSize-2;
			iZLibResult = uncompress(unpack+2,&unpackedsize,pBuffer+2,nPacketLen-2);
			nNewSize *= 2;
		}while(iZLibResult == Z_BUF_ERROR && nNewSize < 250000);

		if(iZLibResult == Z_OK)
		{
			unpack[0] = OP_KADEMLIAHEADER;
			unpack[1] = pBuffer[1];
			processOriginalPacket(unpack,
				unpackedsize+2,
				addrULong,
				port,
				GetUDPVerifyKey(addrULong)==nReceiverVerifyKey,
				KadUDPKey(nSenderVerifyKey,0)
				);
		}
		else
		{
			DEBUG_PRINT2("ZLib compressed data error occured ,from node %s\n",(inet_ntoa(*((in_addr*)&addrULong))));
		}
		delete[] unpack;
	}
	else
	{
		throw string("Kad Packet(compressed) too short");
	}
}

void KadScanner::processOriginalPacket(BYTE *data, uint32 dataLen, uint32 ipaddr, uint16 port, bool validReceiveKey, KadUDPKey senderUDPKey)
{
	if(dataLen <= 2)
	{
        ostringstream stream;
        stream<<"Kad packet too short ";
        stream<<KadCrawl::KadUtil::getFullIpGeoInfoFromIP(ipaddr);
		throw stream.str();
		return;
	}

	BYTE* pData = data+2;
	uint32 uLenData = dataLen-2;
	BYTE byOpcode = data[1];
    kadAnalyzer.countIncomingMessageType(byOpcode);
   	vector<KADEMLIA2_Handler> handlers = handlersMap[byOpcode];
    for(unsigned int i=0;i<handlers.size();i++)
    {
        KADEMLIA2_Handler handler = handlers[i];
		handler(ipaddr,data,dataLen);
    }
    std::ostringstream stream;
	switch(byOpcode)
	{
    case KADEMLIA_BOOTSTRAP_REQ_DEPRECATED:
        //DEBUG_PRINT1("received KAD_BOOTSTRAP_REQ_DEPRECATED \n");
        break;
	case KADEMLIA2_BOOTSTRAP_REQ:
		DEBUG_PRINT1("received KAD2_BOOTSTRAP_REQ \n");
		break;
    case KADEMLIA_BOOTSTRAP_RES_DEPRECATED:
		//DEBUG_PRINT1("received KAD_BOOTSTRAP_RES \n");
        Process_KADEMLIA_BOOTSTRAP_RES_DEPRECATED(pData,uLenData,ipaddr,port,senderUDPKey);
        break;
	case KADEMLIA2_PING:
		DEBUG_PRINT1("received KAD2_PING request\n");
		Process_KADEMLIA2_PING(pData,uLenData,ipaddr,port,senderUDPKey);
		break;
	case KADEMLIA2_PONG:
		//DEBUG_PRINT1("received KAD2_PONG\n");
        //stream<<"received KAD2_PONG";
		Process_KADEMLIA2_PONG(pData,uLenData,ipaddr,port,senderUDPKey);
		break;
	case KADEMLIA2_HELLO_RES:
		//DEBUG_PRINT1("received KAD2_HELLO_RES message response\n");
		Process_KADEMLIA2_HELLO_RES(pData,uLenData,ipaddr,port,senderUDPKey);
		break;
    case KADEMLIA2_HELLO_RES_ACK:
		DEBUG_PRINT1("received KAD2_HELLO_RES_ACK message response\n");
	case KADEMLIA2_HELLO_REQ:
		//DEBUG_PRINT1("received KAD2_HELLO_REQ message response\n");
		Process_KADEMLIA2_HELLO_REQ(pData,uLenData,ipaddr,port,senderUDPKey);
		break;
	case KADEMLIA_FIREWALLED2_REQ:
		//DEBUG_PRINT1("received KADEMLIA_FIREWALLED2_REQ message response\n");
		break;
	case KADEMLIA_FIREWALLED_REQ:
		DEBUG_PRINT1("received KAD_FIREWALLED_REQ message response\n");
		break;
    case KADEMLIA_FIREWALLED_RES:
        DEBUG_PRINT1("received KAD_FIREWALLED2_RES message response\n");
        break;
    case KADEMLIA_FINDBUDDY_REQ:
        DEBUG_PRINT1("received KAD_FINDBUDDY_REQ message response\n");
        Process_KADEMLIA_FINDBUDDY_RES(pData,uLenData,ipaddr,port,senderUDPKey);
        break;
	case KADEMLIA_FINDBUDDY_RES:
		DEBUG_PRINT1("received KAD_FINDBUDDY_RES message response\n");
		Process_KADEMLIA_FINDBUDDY_RES(pData,uLenData,ipaddr,port,senderUDPKey);
		break;
    case KADEMLIA_CALLBACK_REQ:
		DEBUG_PRINT1("received KAD_CALLBACK_REQ message response\n");
        break;
	case KADEMLIA2_RES:
		//DEBUG_PRINT1("received KAD2 RES message response\n");
		Process_KADEMLIA2_RES(pData,uLenData,ipaddr,port,senderUDPKey);
		break;
	case KADEMLIA2_REQ:
		//DEBUG_PRINT1("received KAD2 REQ message response\n");
		Process_KADEMLIA2_REQ(pData,uLenData,ipaddr,port,senderUDPKey);
		break;
	case KADEMLIA2_BOOTSTRAP_RES:
		//DEBUG_PRINT1("received KAD2 BOOTSTRAP RES message response\n");
		Process_KADEMLIA2_BOOTSTRAP_RES(pData,uLenData,ipaddr,port,senderUDPKey);
		break;
	case KADEMLIA2_SEARCH_RES:
		DEBUG_PRINT1("received KAD2_SEARCH_RES message response\n");
		Process_KADEMLIA2_SEARCH_RES(pData,uLenData,ipaddr,port,senderUDPKey);
		break;
    case KADEMLIA2_PUBLISH_KEY_REQ:
		DEBUG_PRINT1("received KAD2_PUBLISH_KEY_REQ message response\n");
        Process_KADEMLIA2_PUBLISH_KEY_REQ(pData,uLenData,ipaddr,port,senderUDPKey);
        break;
    case KADEMLIA2_PUBLISH_SOURCE_REQ:
		DEBUG_PRINT1("received KAD2_PUBLISH_SOURCE_REQ message response\n");
        break;
    case KADEMLIA2_PUBLISH_NOTES_REQ:
		DEBUG_PRINT1("received KAD2_PUBLISH_NOTES_REQ message response\n");
        break;
    case KADEMLIA2_PUBLISH_RES:
        DEBUG_PRINT1("received KAD2_PUBLISH_RES message response\n");
        break;
    case KADEMLIA2_SEARCH_KEY_REQ:
		DEBUG_PRINT1("received KAD2_SEARCH_KEY_REQ message response\n");
        break;
    case KADEMLIA2_SEARCH_NOTES_REQ:
		DEBUG_PRINT1("received KAD2_SEARCH_NOTES_REQ message response\n");
        break;
    case KADEMLIA2_SEARCH_SOURCE_REQ:
		DEBUG_PRINT1("received KAD2_SEARCH_SOURCE_REQ message response\n");
        break;
    case KADEMLIA_REQ:
        Process_KADEMLIA_REQ(pData,uLenData,ipaddr,port,senderUDPKey);
		//DEBUG_PRINT1("received KAD_REQ message\n");
        break;
    case KADEMLIA_HELLO_REQ:
        //DEBUG_PRINT1("received KAD_HELLO_REQ message\n");
        break;
    case KADEMLIA_PUBLISH_REQ:
        DEBUG_PRINT1("received KAD_PUBLISH_REQ message\n");
        Process_KADEMLIA_PUBLISH_KEY_REQ(pData,uLenData,ipaddr,port,senderUDPKey);
        break;
    case KADEMLIA_SEARCH_REQ:
        DEBUG_PRINT1("received KAD_SEARCH_REQ message\n");
        break;
	default:
		DEBUG_PRINT2("unknown KAD message format: %02lX\n",(ULONG)byOpcode);
		break;
	}
}

void KadScanner::sendPingProbe(KadNode &node)
{
	this->sendPacket(NULL,0,KADEMLIA2_PING,node.ipNetOrder,node.udp_port,node.kadUDPkey,&node.kad_id);
}

void KadScanner::sendBootstrapReq(KadNode &node)
{
	if(node.version > 1)
	{
		if(node.version >= KADEMLIA_VERSION6_49aBETA)
			this->sendPacket(NULL,0,KADEMLIA2_BOOTSTRAP_REQ,node.ipNetOrder,node.udp_port,0,&node.kad_id);
		else
			this->sendPacket(NULL,0,KADEMLIA2_BOOTSTRAP_REQ,node.ipNetOrder,node.udp_port,0,NULL);
	}
}

void KadScanner::SendMyDetails(uint8 byOpcode,KadNode& node,bool requestAck,uint8 version)
{
	if(version>1)
	{
		SafeMemFile fileIO;
		fileIO.WriteUInt8(OP_KADEMLIAHEADER);
		fileIO.WriteUInt8(byOpcode);
		fileIO.WriteUInt128(&KadUtil::kad_id);
		fileIO.WriteUInt16(KadCrawl::KadUtil::udp_port);
		fileIO.WriteUInt8(KADEMLIA_VERSION9_50a);

		uint8 by_tagCount=1;
		if(version >= KADEMLIA_VERSION8_49b)
			by_tagCount++;
		fileIO.WriteUInt8(by_tagCount);

		KadTagUInt16 tagSrcPort(TAG_SOURCEUPORT,KadCrawl::KadUtil::udp_port);
		fileIO.WriteTag(&tagSrcPort);

		if(version >= KADEMLIA_VERSION8_49b)
		{
			const uint8 udpFirewalled = 0;
			const uint8 tcpFirewalled = 0;
			const uint8 uRequestACK = 0;
			const uint8 miscOptions = (uRequestACK<<2)|(tcpFirewalled<<1)|(udpFirewalled<<0);
			KadTagUInt8 tagMisc(TAG_KADMISCOPTIONS,miscOptions);
			fileIO.WriteTag(&tagMisc);
		}

		if(version >= KADEMLIA_VERSION6_49aBETA)
		{
			if(isnulmd4(node.kad_id.GetDataPtr()))
			{
				sendPacket(fileIO.memBuffer,fileIO.file_size,node.ipNetOrder,node.udp_port,node.kadUDPkey,NULL);
			}
			else
			{
				sendPacket(fileIO.memBuffer,fileIO.file_size,node.ipNetOrder,node.udp_port,node.kadUDPkey,&node.kad_id);
			}
		}
		else
		{
			sendPacket(fileIO.memBuffer,fileIO.file_size,node.ipNetOrder,node.udp_port,0,NULL);
		}
	}
	else
	{
        SafeMemFile fileIO;
		fileIO.WriteUInt128(&KadCrawl::KadUtil::kad_id);
        fileIO.WriteUInt32(0);
        fileIO.WriteUInt16(KadCrawl::KadUtil::udp_port);
        fileIO.WriteUInt16(KadCrawl::KadUtil::udp_port);
        fileIO.WriteUInt8(0);
	    sendPacket(fileIO.memBuffer,fileIO.file_size,byOpcode,node.ipNetOrder,node.udp_port,0,NULL);
	}
}

void KadScanner::SendDetailsWithIdentity(uint8 byOpcode,KadNode& node,KadNode& sybil_node,bool requestAck,uint8 version)
{
	if(version>1)
	{
		SafeMemFile fileIO;
		fileIO.WriteUInt8(OP_KADEMLIAHEADER);
		fileIO.WriteUInt8(byOpcode);
		fileIO.WriteUInt128(&sybil_node.kad_id);
		fileIO.WriteUInt16(sybil_node.udp_port);
		fileIO.WriteUInt8(KADEMLIA_VERSION9_50a);

		uint8 by_tagCount=1;
		if(version >= KADEMLIA_VERSION8_49b)
			by_tagCount++;
		fileIO.WriteUInt8(by_tagCount);

		KadTagUInt16 tagSrcPort(TAG_SOURCEUPORT,sybil_node.udp_port);
		fileIO.WriteTag(&tagSrcPort);

		if(version >= KADEMLIA_VERSION8_49b)
		{
			const uint8 udpFirewalled = 1;
			const uint8 tcpFirewalled = 1;
			const uint8 uRequestACK = 0;
			const uint8 miscOptions = (uRequestACK<<2)|(tcpFirewalled<<1)|(udpFirewalled<<0);
			KadTagUInt8 tagMisc(TAG_KADMISCOPTIONS,miscOptions);
			fileIO.WriteTag(&tagMisc);
		}

		if(version >= KADEMLIA_VERSION6_49aBETA)
		{
			if(isnulmd4(node.kad_id.GetDataPtr()))
			{
				sendPacket(fileIO.memBuffer,fileIO.file_size,node.ipNetOrder,node.udp_port,node.kadUDPkey,NULL);
			}
			else
			{
				sendPacket(fileIO.memBuffer,fileIO.file_size,node.ipNetOrder,node.udp_port,node.kadUDPkey,&node.kad_id);
			}
		}
		else
		{
			sendPacket(fileIO.memBuffer,fileIO.file_size,node.ipNetOrder,node.udp_port,0,NULL);
		}
	}
	else
	{
        SafeMemFile fileIO;
		fileIO.WriteUInt128(&sybil_node.kad_id);
        fileIO.WriteUInt32(0);
        fileIO.WriteUInt16(sybil_node.udp_port);
        fileIO.WriteUInt16(sybil_node.udp_port);
        fileIO.WriteUInt8(0);
	    sendPacket(fileIO.memBuffer,fileIO.file_size,byOpcode,node.ipNetOrder,node.udp_port,0,NULL);
	}
}

void KadScanner::sendNodeLookupReq(CUInt128& target,KadNode &node, uint8 requestCount)
{
	uchar buffer[33]={0};
	memcpy(buffer,&requestCount,sizeof(requestCount));
	memcpy(buffer+1,target.GetData(),sizeof(char)*16);
	memcpy(buffer+17,node.kad_id.GetData(),sizeof(char)*16);

	this->sendPacket(buffer,33,KADEMLIA2_REQ,node.ipNetOrder,node.udp_port,node.kadUDPkey,&node.kad_id);

}
void KadScanner::sendKeywordTargetLookupReq(string keyword,KadNode &node)
{
	CUInt128 target_id = KadUtil::getInt128FromString(keyword);
	
	SafeMemFile fileIO(33);
	unsigned int req_count = 2;

	fileIO.WriteUInt8(req_count);
	fileIO.WriteUInt128(&target_id);
	fileIO.WriteUInt128(&node.kad_id);
	
	this->sendPacket(fileIO.memBuffer,fileIO.file_size,KADEMLIA2_REQ,node.ipNetOrder,node.udp_port,node.kadUDPkey,&node.kad_id);
}
void KadScanner::sendKeywordLookupReq(string keyword,KadNode &node)
{
	MD4 md4_c;
	BYTE msg[16];
	md4_c.Update((byte*)keyword.c_str(),keyword.size());
	md4_c.Final(msg);

	CUInt128 target_id;
	target_id.SetValueBE(msg);

	SafeMemFile fileIO(33);
	unsigned int req_count = 2;
	
	fileIO.WriteUInt128(&target_id);
	fileIO.WriteUInt16((uint16)0x0000);

	this->sendPacket(fileIO.memBuffer,fileIO.file_size,KADEMLIA2_SEARCH_KEY_REQ,node.ipNetOrder,node.udp_port,node.kadUDPkey,&node.kad_id);
}

void KadScanner::sendFindBuddyReq(KadNode& node)
{
	SafeMemFile fileIO;
	fileIO.WriteUInt128(&CUInt128(true).Xor(KadUtil::kad_id));
	fileIO.WriteUInt128(&KadUtil::client_hash);
	fileIO.WriteUInt16(KadCrawl::KadUtil::udp_port);
	if(node.version >= 6)
		this->sendPacket(fileIO.memBuffer,fileIO.file_size,KADEMLIA_FINDBUDDY_REQ,node.ipNetOrder,node.udp_port,node.kadUDPkey,&node.kad_id);
	else
		this->sendPacket(fileIO.memBuffer,fileIO.file_size,KADEMLIA_FINDBUDDY_REQ,node.ipNetOrder,node.udp_port,0,NULL);
}

void KadScanner::sendStoreKeywordRequest(KadNode& node,string keyword_para)
{
	string keyword = s2utfs(keyword_para);
	MD4 md4_c;
	BYTE msg[16];
	md4_c.Update((byte*)keyword.c_str(),keyword.size());
	md4_c.Final(msg);

	CUInt128 target_id;
	target_id.SetValueBE(msg);

	SafeMemFile fileIO;
	fileIO.WriteUInt128(&target_id);
	fileIO.WriteUInt16(0);

	this->sendPacket(fileIO.memBuffer,fileIO.file_size,KADEMLIA2_PUBLISH_KEY_REQ,node.ipNetOrder,node.udp_port,node.kadUDPkey,&node.kad_id);
}

void KadScanner::sendSearchFileSourceRequest(KadSharedFile& file)
{
	list<KadNode> neighbors = KadUtil::GetNeighboringNodes(nodeList,file.fileHash,20);
	//list<KadNode>& neighbors = nodeList;

	for(list<KadNode>::iterator it = neighbors.begin();it != neighbors.end();it++)
	{
		KadNode& node = *it;
		SafeMemFile fileIO;
		fileIO.WriteUInt128(&file.fileHash);
		fileIO.WriteUInt16(0);
		fileIO.WriteUInt64(file.fileSize);
		if(node.version >= KADEMLIA_VERSION6_49aBETA)
		{
			this->sendPacket(fileIO.memBuffer,fileIO.file_size,KADEMLIA2_SEARCH_SOURCE_REQ,node.ipNetOrder,node.udp_port,node.kadUDPkey,&node.kad_id);
		}
		else
			this->sendPacket(fileIO.memBuffer,fileIO.file_size,KADEMLIA2_SEARCH_SOURCE_REQ,node.ipNetOrder,node.udp_port,0,NULL);
	}
}

/*
void KadScanner::CrawleSingleNode(CUInt128 target_id,uint32 ip,uint16 uUDPPort)
{
	
}
*/
// deeply involved in requesting further information about files shared by remote host
void KadScanner::interactWithPeerForFileInfo(KadNode& node)
{
	
}	
void KadScanner::Process_KADEMLIA2_PING(const BYTE* data,uint32 uLen,uint32 ip, uint16 uUDPPort, KadUDPKey key)
{
	this->sendPacket((unsigned char*)&uUDPPort,2,KADEMLIA2_PONG,ip,uUDPPort,key,NULL);
}
void KadScanner::Process_KADEMLIA2_PONG(const BYTE* data,uint32 uLen,uint32 ip, uint16 uUDPPort, KadUDPKey key)
{
    SimpleKadNode node(KadCrawl::KadUtil::kad_id,uUDPPort,ip);
    tempKadNodeList.push_back(node);
}
void KadScanner::Process_KADEMLIA2_HELLO_REQ(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key)
{
	SafeMemFile fileIO(data,uLen);
	CUInt128 uID;
	fileIO.ReadUInt128(&uID);
	uint16 uTCPPort = fileIO.ReadUInt16();
	uint8 uVersion = fileIO.ReadUInt8();

	uint8 outVersion = 0;

	uint8 uTags = fileIO.ReadUInt8();
	bool bUDPFirewalled = false;
	bool bTCPFirewalled = false;

	bool bOutRequestACK = false;

	while(uTags)
	{
		KadTag* pTag = fileIO.ReadTag();
		if(pTag == NULL)
		{
			--uTags;
			std::ostringstream stream;
			stream<<"KadScanner invalid tag in KADEMLIA2_HELLO_REQ from ip ";
			stream<<inet_ntoa(*((struct in_addr*)&ip))<<" "<<uUDPPort;
			stream<<" tag array size "<<(uTags+1);
			KadLogger::Log(WARN_KAD_LOG,stream.str());
			break;
		}
		if(!(pTag->m_name == TAG_SOURCEUPORT))
		{
			if(pTag->IsInt() && (uint16)pTag->GetInt()>0)
				uUDPPort = (uint16)pTag->GetInt();
		}

		if(!(pTag->m_name == TAG_KADMISCOPTIONS))
		{
			if(pTag->IsInt() && (uint16)pTag->GetInt()>0)
			{
				bUDPFirewalled = (pTag->GetInt()&0x01)>0;
				bTCPFirewalled = (pTag->GetInt()&0x02)>0;
				if((pTag->GetInt()&0x04)>0 && uVersion >= KADEMLIA_VERSION8_49b)
				{
					bOutRequestACK = true;
				}
			}
		}
		delete pTag;
		--uTags;
	}
	
	in_addr addr;
#ifdef WIN32
	addr.S_un.S_addr = ip;
#else
	addr.s_addr = ip;
#endif

    if(!processImmediatelly)
    {
        std::ostringstream stream;
        char* ip_str = inet_ntoa(addr);
        stream<<"This peer send KAD2_HELLO message to us: "<<uID.ToHexString().c_str()<<" ,ip:"<<ip_str;
        stream<<" country: "<<KadCrawl::KadUtil::getFullIpGeoInfoFromIP(ip);
        stream<<" udp port: "<<uUDPPort<<" ,tcp port: "<<uTCPPort;
        stream<<" udp firewalled "<<bUDPFirewalled<<" ,tcp firewalled "<<bTCPFirewalled;
        KadLogger::Log(DEBUG_KAD_LOG,stream.str());
        DEBUG_PRINT2("%s\n",stream.str().c_str());
    }
    if(interactive)
    {
        KadNode node;
        node.kad_id = uID;
        node.udp_port = KadCrawl::KadUtil::udp_port;
        node.tcp_port = KadCrawl::KadUtil::udp_port;
        node.ipNetOrder = ip;
        node.version = uVersion;
        SendMyDetails(KADEMLIA2_HELLO_RES,node,false,node.version);
    }

    KadNode node;
    node.kad_id = uID;
    node.ipNetOrder = ip;
    node.udp_port = uUDPPort;
    node.tcp_port = uTCPPort;
    node.version = uVersion;
    boost::mutex::scoped_lock(activeKadNodeListLock);
    activeKadNodeList.push_back(node);
}

void KadScanner::Process_KADEMLIA2_HELLO_RES(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key)
{
	SafeMemFile fileIO(data,uLen);

	CUInt128 sourceID;
	fileIO.ReadUInt128(&sourceID);
	uint16 tcp_port = fileIO.ReadUInt16();
	uint8 uVersion = fileIO.ReadUInt8();

	uint8 uTags = fileIO.ReadUInt8();

	bool bUDPFirewalled = false;
	bool bTCPFirewalled = false;

	bool bOutRequestACK = false;

	while(uTags)
	{
		KadTag* pTag = fileIO.ReadTag();
        if(pTag == NULL)
        {
            throw string("Invalid tag in taglist packet");
            return;
        }
		if(!(pTag->m_name == TAG_SOURCEUPORT))
		{
			if(pTag->IsInt() && (uint16)pTag->GetInt()>0)
				uUDPPort = (uint16)pTag->GetInt();
		}

		if(!(pTag->m_name == TAG_KADMISCOPTIONS))
		{
			if(pTag->IsInt() && (uint16)pTag->GetInt()>0)
			{
				bUDPFirewalled = (pTag->GetInt()&0x01)>0;
				bTCPFirewalled = (pTag->GetInt()&0x02)>0;
				if((pTag->GetInt()&0x04)>0 && uVersion >= KADEMLIA_VERSION8_49b)
				{
					bOutRequestACK = true;
				}
			}
		}
		delete pTag;
		--uTags;
	}

	if(bOutRequestACK)
	{
		SafeMemFile fileIO(17);
		fileIO.WriteUInt128(&KadUtil::kad_id);
		fileIO.WriteUInt8(0);
		//sendPacket(fileIO.memBuffer,fileIO.file_size,KADEMLIA2_HELLO_RES_ACK,ip,uUDPPort,key,NULL);
	}
	SimpleKadNode node(sourceID,uUDPPort,ip);
	tempKadNodeList.push_back(node);
}

void KadScanner::Process_KADEMLIA2_BOOTSTRAP_REQ(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key)
{
	std::ostringstream stream;
	stream<<"This peer send KAD2_BOOTSTRAP_REQ message to us: "<<inet_ntoa(*((in_addr*)&ip))<<" udp port: "<<uUDPPort;
	KadLogger::Log(DEBUG_KAD_LOG,stream.str());
	DEBUG_PRINT2("%s\n",stream.str().c_str());
}

void KadScanner::Process_KADEMLIA2_REQ(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key)
{
	SafeMemFile fileIO(data,uLen);

	uint8 version = fileIO.ReadUInt8();
	version &= 0x1F;
	if(version == 0)
	{
		DEBUG_PRINT2("Wrong version of message: %d\n",version);
		return;
	}

	CUInt128 uTarget;
	fileIO.ReadUInt128(&uTarget);
    if(!processImmediatelly)
    {
        std::ostringstream stream;
        stream<<"This peer send KAD2_REQ message to us: "<<uTarget.ToHexString().c_str()<<" ,ip:"<<inet_ntoa(*((in_addr*)&ip))<<" udp port: "<<uUDPPort;
        KadLogger::Log(DEBUG_KAD_LOG,stream.str());
    }
	//DEBUG_PRINT2("%s\n",stream.str().c_str());
    KadNode node;
    node.kad_id = uTarget;
    node.udp_port = uUDPPort;
    node.ipNetOrder = ip;
    boost::mutex::scoped_lock(activeRouteQueryKadNodeListLock);
    activeRouteQueryKadNodeList.push_back(node);
}

void KadScanner::Process_KADEMLIA_FIREWALLED2_REQ(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key)
{
	std::ostringstream stream;
	stream<<"This peer send KADEMLIA_FIREWALLED2_REQ message to us: "<<" ,ip:"<<inet_ntoa(*((in_addr*)&ip))<<" udp port: "<<uUDPPort;
	KadLogger::Log(DEBUG_KAD_LOG,stream.str());
	DEBUG_PRINT2("%s\n",stream.str().c_str());
}

void KadScanner::Process_KADEMLIA2_RES(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key)
{
	SafeMemFile fileIO(data,uLen);

	CUInt128 uTarget;
	fileIO.ReadUInt128(&uTarget);

    SimpleKadNode respondingNode(uTarget,uUDPPort,ip);
    respondingNodeList.push_back(respondingNode);
    
	uint8 uNumContacts = fileIO.ReadUInt8();

	if(uNumContacts > 11)
	{
		//DEBUG_PRINT2("Received Peers Exceeds 11 :%d\n",uNumContacts);
	}

	//gradual_count.push_back(uNumContacts);
#ifndef _OPENMP
    incomingPeerCount++;   
    if(incomingPeerCount%1000==0)
    {
        std::ostringstream stream;
        stream<<"packets received come to a thousand ";
        stream<<incomingPeerCount;
        DEBUG_PRINT2("%s\n",stream.str().c_str());
    }
#endif
	if(uLen != (UINT)(16+1+(16+4+2+2+1)*uNumContacts))
	{
		in_addr addr;
#ifdef WIN32
		addr.S_un.S_addr = ip;
#else
		addr.s_addr = ip;
#endif
		DEBUG_PRINT2("KADEMLIA2_RES message length error,%s",inet_ntoa(addr));
		return;
	}

	CUInt128 uIDResult;
	for(uint8 index=0;index<uNumContacts;index++)
	{
		fileIO.ReadUInt128(&uIDResult);
		uint32 uIPResult = fileIO.ReadUInt32();
		uint16 uUDPPortResult = fileIO.ReadUInt16();
		uint16 uTCPPortResult = fileIO.ReadUInt16();
		uint8 uVersion = fileIO.ReadUInt8();
		uint32 uhostIPResult = htonl(uIPResult);

		bool bVerified = false;
		//bool WasAdded = routingZone->AddUnfiltered(uIDResult,uhostIPResult,uUDPPortResult,uTCPPortResult,uVersion,0,bVerified);
		if(uIDResult == routingZone->uMe)
			return ;
		KadNode target_node = KadNode(uIDResult,uhostIPResult,uUDPPortResult,uTCPPortResult,KadUtil::kad_id,uVersion,0,bVerified,ip);
				
		Edge edge(ip,uhostIPResult);
		//edgeList.push_back(edge);

		boost::mutex::scoped_lock lock(nodeListLock);
        putNodeToTempList(target_node);
	}
}
void KadScanner::Process_KADEMLIA2_BOOTSTRAP_RES(const BYTE* data,uint32 uLen,uint32 ip,uint16 uUDPPort,KadUDPKey key)
{
	SafeMemFile fileIO(data,uLen);

	CUInt128 uTarget;
	fileIO.ReadUInt128(&uTarget);
	uint16 uTCPPort = fileIO.ReadUInt16();
	uint8 uVersion = fileIO.ReadUInt8();

    SimpleKadNode respondingNode(uTarget,uUDPPort,ip);
    respondingNodeList.push_back(respondingNode);

	uint16 uNumContacts = fileIO.ReadUInt16();
	while(uNumContacts)
	{
		CUInt128 nodeID;
		fileIO.ReadUInt128(&nodeID);
		uint32 uIP = htonl(fileIO.ReadUInt32());
		uint16 uUDPPort = fileIO.ReadUInt16();

		uint16 uTCPPort = fileIO.ReadUInt16();
		uint8 uVersion = fileIO.ReadUInt8();
		KadNode target_node(nodeID,uIP,uUDPPort,uTCPPort,KadUtil::kad_id,uVersion,0,false,ip);

		Edge edge(ip,uIP);
		//edgeList.push_back(edge);
		boost::mutex::scoped_lock lock(nodeListLock);
        putNodeToTempList(target_node);
		lock.unlock();
		uNumContacts--;
	}
}
void KadScanner::Process_KADEMLIA_BOOTSTRAP_RES_DEPRECATED(const BYTE* data,uint32 uLen,uint32 ip,uint16 uUDPPort,KadUDPKey key)
{
    if(uLen < 27)
    {
        std::ostringstream stream;
        stream<<"Bootstrap Length Not Equals 25 Error";
        throw stream.str();
    }
    SafeMemFile fileIO(data,uLen);
	uint16 uNumContacts = fileIO.ReadUInt16();
    if(uLen != (2+25*uNumContacts))
    {
        if(uLen==527)
        {
            uNumContacts++;
        }
        else
        {
            std::ostringstream stream;
            stream << "Bootstrap Length Not Valid with length "<<uLen<<" and assumed size of contacts "<<uNumContacts;
            throw stream.str();
        }
    }
    SafeMemFile contactsIO(data+2,uLen-2);
    CUInt128 id;
    for(uint16 i=0;i<uNumContacts;i++)
    {
        contactsIO.ReadUInt128(&id);    
        uint32 ip = contactsIO.ReadUInt32();
        uint16 port = contactsIO.ReadUInt16();
        uint16 tport = contactsIO.ReadUInt16();
        uint8 type = contactsIO.ReadUInt8();
        KadNode node;
        node.ipNetOrder = htonl(ip);
        node.udp_port = port;
        node.tcp_port = tport;
        node.version = 0;
        node.node_type = type;

        boost::mutex::scoped_lock lock(nodeListLock);
        putNodeToTempList(node);
		lock.unlock();
    }
}

bool searchByFileHash(KadSharedFile fileA,KadSharedFile fileB)
{
	return fileA.fileHash<fileB.fileHash;
}

void KadScanner::Process_KADEMLIA2_SEARCH_RES(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key)
{
	SafeMemFile dataIO(data,uLen);

	// Who sent this packet
	CUInt128 uSource;
	dataIO.ReadUInt128(&uSource);
	// What search does this relate to,keyword id
	CUInt128 uTarget;
	dataIO.ReadUInt128(&uTarget);

	// Total results
	uint16 uCount = dataIO.ReadUInt16();

	CUInt128 uAnswer;
	
	while(uCount > 0)
	{
		// What is the answer,the node which the file reside on
		dataIO.ReadUInt128 (&uAnswer);
		TagList* pTags = new TagList;
		dataIO.ReadTagList(pTags);
		
		switch(searchResultType)
		{
		case SEARCH_KEYWORD:
			{
				boost::mutex::scoped_lock lock(fileListLock);		
				fileList.sort();
				KadSharedFile searchFile;
				searchFile.fileHash = uAnswer;
				list<KadSharedFile>::iterator it = 
					std::lower_bound(fileList.begin(),fileList.end(),searchFile,searchByFileHash);

				KadKeywordNode kNode;
				kNode.srcNodeID = uSource;
				kNode.srcNodeIP = ip;
				kNode.srcNodeUdpPort = uUDPPort;

				if(it != fileList.end() && (*it).fileHash==uAnswer)
				{
					KadSharedFile &kadFile = *it;
					Process_KADEMLIA_SEARCHRESULT_KEYWORD(kadFile,kNode,uAnswer,pTags,ip,uUDPPort);
				}
				else
				{
					KadSharedFile kadFile;
					kadFile.fileHash = uAnswer;
					kadFile.keywordID = uTarget;
					Process_KADEMLIA_SEARCHRESULT_KEYWORD(kadFile,kNode,uAnswer,pTags,ip,uUDPPort);
					fileList.push_back(kadFile);
				}
			}
			break;
		case SEARCH_FILE:
			{
				KadSharedFile searchFile;
				searchFile.fileHash = uTarget;
				boost::mutex::scoped_lock lock(fileListLock);		
				fileList.sort();

				list<KadSharedFile>::iterator it = 
					std::lower_bound(fileList.begin(),fileList.end(),searchFile,searchByFileHash);
				
				if(it != fileList.end() && (*it).fileHash==uTarget)
				{
					KadSharedFile& targetFile = *it;
					Process_KADEMLIA_SEARCHRESULT_SOURCE(targetFile,uAnswer,pTags,ip,uUDPPort);
				}
				else
				{
					std::ostringstream stream;
					stream<<"search result source did not match any keyword search result ";
					stream<<inet_ntoa(*((in_addr*)&ip))<<" :"<<uUDPPort;
					KadLogger::Log(WARN_KAD_LOG,stream.str());
				}
			}
			break;
		case SEARCH_NOTES:
			break;
		}
		delete pTags;
		uCount--;
	}
}

void KadScanner::Process_KADEMLIA_SEARCHRESULT_KEYWORD(KadSharedFile& kadFile,KadKeywordNode& kNode,CUInt128 uAnswer,TagList* pTags,uint32 ip,uint16 udp_port)
{
	bool bFileName = false;
	bool bFileSize = false;

	string sName;
	string sType;
	uint64 uSize=0;
	string sFormat;
	string sArtist;
	string sAlbum;
	string sTitle;
	string sCodec;
	uint32 uBitrate=0;
	uint32 uPublishInfo=0;
	uint32 uAvailability=0;
	uint32 uLength = 0;

	std::ostringstream stream;

	TagList::iterator itTagList;
	for(itTagList=pTags->begin();itTagList!=pTags->end();itTagList++)
	{
		KadTag* pTag = *itTagList;
		if(pTag->m_name == TAG_FILENAME)
		{
			sName = pTag->GetStr();
			bFileName = true;
		}
		else if(pTag->m_name == TAG_FILESIZE)
		{
			if(pTag->IsBsob() && pTag->GetBsobSize() == 8)
				uSize = *((uint64*)pTag->GetBsob());
			else
				uSize = pTag->GetInt();
			bFileSize = true;
		}
		else if(pTag->m_name == TAG_FILETYPE)
		{
			sType = pTag->GetStr();
		}
		else if(pTag->m_name == TAG_MEDIA_ARTIST)
		{
			sArtist = pTag->GetStr();
		}
		else if(pTag->m_name == TAG_MEDIA_ALBUM)
		{
			sAlbum = pTag->GetStr();
		}
		else if(pTag->m_name == TAG_MEDIA_TITLE)
		{
			sTitle = pTag->GetStr();
		}
		else if(pTag->m_name == TAG_MEDIA_LENGTH)
		{
			uLength = (uint32)pTag->GetInt();
		}
		else if(pTag->m_name == TAG_MEDIA_BITRATE)
		{
			uBitrate = (uint32)pTag->GetInt();
		}
		else if(pTag->m_name == TAG_MEDIA_CODEC)
		{
			sCodec = pTag->GetStr();
		}
		else if(pTag->m_name == TAG_SOURCES)
		{
			uAvailability = (uint32)pTag->GetInt();
			if(uAvailability > 65500)
				uAvailability = 0;
		}
		else if(pTag->m_name == TAG_PUBLISHINFO)
		{
			uPublishInfo = (uint32)pTag->GetInt();
		}
		else
		{
			DEBUG_PRINT2("unknow file attribute type: %s\n",pTag->m_name.c_str());
		}
		delete pTag;
	}

	if(bFileName)
		stream<<"file name: "<<sName<<" ";
	if(bFileSize)
		stream<<"file size: "<<(uSize/(1024*1024)) <<"MB ";
	stream<<"file type:"<<sType<<" ";
	stream<<"media length: "<<uLength/(3600)<<"hours"<<uLength/60<<"minutes"<<uLength%60<<"seconds ";
	stream<<"bitrate: "<<uBitrate/1024 <<"kBit/s ";
	stream<<"codec: "<<sCodec<<" ";
	stream<<endl;
	DEBUG_PRINT2("%s",stream.str().c_str());

	kNode.fileName = sName;
	kNode.media_album = sAlbum;
	kNode.media_artist = sArtist;
	kNode.media_bitrate = uBitrate;
	kNode.media_length = uLength;
	kNode.media_title = sTitle;
	kadFile.fileSize = uSize;
	kadFile.addKadKeywordNode(kNode);
}

void KadScanner::Process_KADEMLIA_SEARCHRESULT_SOURCE(KadSharedFile& kadFile,CUInt128 uAnswer,TagList* pTags,uint32 ip,uint16 udp_port)
{
	uint8 uType = 0;
	uint32 uIP = 0;
	uint16 uTCPPort = 0;
	uint16 uUDPPort = 0;
	uint32 uBuddyIP = 0;
	uint32 uBuddyPort = 0;

	CUInt128 uBuddy;
	uint8 by_cryptOptions = 0;

	TagList::iterator itTagList;
	for(itTagList=pTags->begin();itTagList!=pTags->end();itTagList++)
	{
		KadTag* pTag = *itTagList;
		string tagName = pTag->m_name;
		if(tagName == TAG_SOURCETYPE)
		{
			uType = (uint8)pTag->GetInt();
		}
		else if(tagName == TAG_SOURCEIP)
		{
			uIP = (uint32)pTag->GetInt();
		}
		else if(tagName == TAG_SOURCEUPORT)
		{
			uTCPPort = (uint16)pTag->GetInt();
		}
		else if(tagName == TAG_SOURCEUPORT)
		{
			uUDPPort = (uint16)pTag->GetInt();
		}
		else if(tagName == TAG_SERVERIP)
		{
			uBuddyIP = (uint32)pTag->GetInt();
		}
		else if(tagName == TAG_SERVERPORT)
		{
			uBuddyPort = (uint16)pTag->GetInt();
		}
		else if(tagName == TAG_BUDDYHASH)
		{
			unsigned char buddyHash[16]={0};
			if(pTag->IsStr() && strIsMD4(pTag->GetStr(),buddyHash))
			{
				md4cpy(uBuddy.GetDataPtr(),buddyHash);
			}
		}
		else if(tagName== TAG_ENCRYPTION)
		{

			by_cryptOptions = (uint8)pTag->GetInt();
		}

		delete pTag;
	}

	KadFileSource source;
	source.uType = uType;
	source.serverUdpPort = uUDPPort;
	source.serverTcpPort=0;
	source.buddyID=0;
	source.buddyIP=0;
	source.buddyPort=0;
	source.sourceIP=0;
	switch(uType)
	{
	case 4:
	case 1:
		{
			// NonFirewalled users
			if(uTCPPort == 0)
			{
				KadLogger::Log(WARN_KAD_LOG,"invalid source node from kademlia");
				return;
			}
			source.sourceIP = uIP;
			source.serverTcpPort = uTCPPort;
		}
		break;
	case 2:
		throw string("SEARCHRESULT_TYPE: this type not used");
		break;
	case 5:
	case 3:
		{
			// firewalled client connected to Kad only
			source.sourceIP = uIP;
			source.serverUdpPort = uUDPPort;
			source.serverTcpPort = uTCPPort;
			source.buddyID = uBuddy;
			source.buddyIP = uBuddyIP;
			source.buddyPort = uBuddyPort;
		}
		break;
	case 6:
		{
			// firewalled source which supports direct udp callback
			if((by_cryptOptions & 0x08)==0)
			{
				KadLogger::Log(WARN_KAD_LOG,"received Kad Source type 6(direct callback) which has the direct callback flag not set");
				break;
			}
			source.serverUdpPort = uUDPPort;
			source.sourceIP = uIP;
		}
		break;
	}
	
	kadFile.addKadFileSource(source);
}

void KadScanner::Process_KADEMLIA_FINDBUDDY_RES(const BYTE *data,uint32 uLen,uint32 ip,uint16 uUDPPort,KadUDPKey key)
{
	SafeMemFile fileIO(data,uLen);
	CUInt128 uCheck;
	fileIO.ReadUInt128(&uCheck);
	uCheck.Xor(CUInt128(true));
	if(KadUtil::kad_id == uCheck)
	{
		CUInt128 userID;
		fileIO.ReadUInt128(&userID);
		uint16 uTCPPort = fileIO.ReadUInt16();
		uint8 byConnectOptions = 0;
		if(uLen > 34)
			byConnectOptions = fileIO.ReadUInt8();
	}
}

void KadScanner::Process_KADEMLIA_PUBLISH_KEY_REQ(const BYTE *data,uint32 uLen,uint32 ip,uint16 uUDPPort,KadUDPKey key)
{
    if(uLen < 37)    
    {
        throw "received wrong size of KAD_PUBLISH request";
        return;
    }
    SafeMemFile fileIO(data,uLen);
    CUInt128 uFile;
    fileIO.ReadUInt128(&uFile);
    uint16 uCount = fileIO.ReadUInt16();

    while(uCount > 0)
    {
        CUInt128 target;
        string filename="unknow file";
        uint32 filesize=0;
        uint16 tcp_port=0;

        fileIO.ReadUInt128(&target);
        uint32 tags = fileIO.ReadUInt8();
        while(tags > 0)
        {
            KadTag* tag = fileIO.ReadTag();
            if(tag)
            {
                if(!(tag->m_name==TAG_SOURCETYPE) && tag->m_type==9)
                {
                }
                if(!(tag->m_name == TAG_FILENAME))
                {
                    filename = tag->GetStr();
                }
                if(!(tag->m_name == TAG_FILESIZE))
                {
                    filesize = tag->GetInt();
                }
                if(!(tag->m_name == TAG_SOURCEPORT))
                {
                    tcp_port = tag->GetInt();
                }
                delete tag;
                tag=NULL;
            }
            tags--;
        }
        DEBUG_PRINT7("Kad_PUBLISH File %s  %u tcpport %u udpport %u from %s %s\n",filename.c_str(),(unsigned int)filesize,tcp_port,uUDPPort,inet_ntoa(*((in_addr*)&ip)),KadCrawl::KadUtil::getFullIpGeoInfoFromIP(ip).c_str());
        uCount--;
    }
}

void KadScanner::Process_KADEMLIA2_PUBLISH_KEY_REQ(const BYTE *data,uint32 uLen,uint32 ip,uint16 uUDPPort,KadUDPKey key)
{
    SafeMemFile fileIO(data,uLen);
    CUInt128 uFile;
    fileIO.ReadUInt128(&uFile);
    
    uint16 uCount = fileIO.ReadUInt16();
    CUInt128 uTarget;
    string file_name="unknow file";
    unsigned long file_size=0;
    while(uCount > 0)
    {
        fileIO.ReadUInt128(&uTarget);
        uint32 uTags = fileIO.ReadUInt8();
        if(uTags>0)
        {
            KadTag *pTag = fileIO.ReadTag();
            if(pTag)
            {
                if(pTag->m_name == TAG_FILENAME)
                {
                    file_name = pTag->GetStr();                                             
                }
                else if(pTag->m_name == TAG_FILESIZE)    
                {
                    if(pTag->IsBsob() && pTag->GetBsobSize()==8)
                    {
                        file_size = *((uint64*)pTag->GetBsob());
                    }
                    else
                        file_size = pTag->GetInt();
                }
                else
                {
                    //DEBUG_PRINT3("Kad2_PUBLISH File %s  %u\n",file_name.c_str(),(unsigned int)file_size);
                }        
                delete pTag;
                pTag=NULL;
            }
        }
        uCount--;
    }
    DEBUG_PRINT6("Kad2_PUBLISH File %s  %u from %s %s udpport: %u\n",file_name.c_str(),(unsigned int)file_size,inet_ntoa(*((in_addr*)&ip)),KadCrawl::KadUtil::getFullIpGeoInfoFromIP(ip).c_str(),uUDPPort);
}

void KadScanner::Process_KADEMLIA_REQ(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key)
{
    SafeMemFile fileIO(data,uLen);

	uint8 version = fileIO.ReadUInt8();
	version &= 0x1F;
	if(version == 0)
	{
		DEBUG_PRINT2("Process_KADEMLIA_REQ Wrong version of message: %d\n",version);
		return;
	}

	CUInt128 uTarget;
	fileIO.ReadUInt128(&uTarget);
    if(!processImmediatelly)
    {
        std::ostringstream stream;
        stream<<"This peer send KAD2_REQ message to us: "<<uTarget.ToHexString().c_str()<<" ,ip:"<<inet_ntoa(*((in_addr*)&ip))<<" udp port: "<<uUDPPort;
        KadLogger::Log(DEBUG_KAD_LOG,stream.str());
    }
	//DEBUG_PRINT2("%s\n",stream.str().c_str());
    KadNode node;
    node.kad_id = uTarget;
    node.udp_port = uUDPPort;
    node.ipNetOrder = ip;
    boost::mutex::scoped_lock(activeDeprecatedKadNodeListLock);
    activeDeprecatedKadNodeList.push_back(node);
}

string KadScanner::DumpRoutingZoneInfo()
{
	return routingZone->dumpInfo("");
}
string KadScanner::DumpKadSharedFiles()
{
	std::ostringstream stream;
	for(list<KadSharedFile>::iterator it=fileList.begin();it!=fileList.end();it++)
	{
		KadSharedFile kFile = *it;
		stream<<kFile.dumpInfo();
	}
	return stream.str();
}

void KadScanner::saveNodesInfoToFile(string filepath,unsigned int version)
{
	KadUtil::saveNodesInfoToFile(filepath,version,nodeList);
}

ULONG KadScanner::GetNodesSize()
{
	ContactList list;
	routingZone->EnumerateAllNodes(list);
	if(list.size() == 0)
		return nodeList.size();
	return list.size();
}

list<SimpleKadNode> KadScanner::GetTempLiveNodes()
{
	boost::mutex::scoped_lock lock(tempNodeListLock);
	return tempKadNodeList;
}
list<KadNode> KadScanner::GetActiveKadNode()
{
    boost::mutex::scoped_lock lock(activeKadNodeListLock);
    return activeKadNodeList;
}

list<KadNode> KadScanner::GetActiveRouteQueryNodeList()
{
    boost::mutex::scoped_lock lock(activeRouteQueryKadNodeListLock);
    return activeRouteQueryKadNodeList;
}
list<KadNode> KadScanner::GetActiveFirewallRequestNodeList()
{
    boost::mutex::scoped_lock lock(activeFirewallReqNodeListLock);
    return activeFirewallReqNodeList;
}
list<KadNode> KadScanner::GetActiveDeprecatedKadNodeList()
{
    boost::mutex::scoped_lock lock(activeDeprecatedKadNodeListLock);
    return activeDeprecatedKadNodeList;
}
list<KadSharedFile> KadScanner::GetSharedFileList()
{
	return fileList;
}
const list<SimpleKadNode>& KadScanner::GetBootstrapRespondingKadNodeList()
{
    KadCrawl::KadUtil::removeDuplicates(respondingNodeList);
    return respondingNodeList;
}
void KadScanner::setAsioServer(AsioUDPServer* server)
{
	this->asioServer = server;
}
void KadScanner::setAsioTcpServer(AsioTCPServer* server)
{
	this->asioTcpServer = server;
}
AsioTCPServer* KadScanner::getTcpEngine()
{
	return asioTcpServer;
}
AsioUDPServer* KadScanner::getUdpEngine()
{
	return asioServer;
}
bool kadNodeLesser(const KadNode& nodeA,const KadNode& nodeB)
{
	return nodeA<nodeB;
}

void KadScanner::processBufferedListAndUpdate()
{
    list<small_packet> bufferedList = this->ExtractBufferedPacketList();    
    std::ostringstream stream;
    stream<<"Total Packets in buffer pool :"<<bufferedList.size();
    KadLogger::Log(INFO_KAD_LOG,stream.str());
    list<small_packet>::iterator it = bufferedList.begin(); 
    for(;it!=bufferedList.end();)
    {
        small_packet packet = *it;
        struct sockaddr_in addr;
    	addr.sin_family = AF_INET;
    	addr.sin_port = packet.source_port;
#ifdef WIN32
    	addr.sin_addr.S_un.S_addr = packet.source_ip;
#else
    	addr.sin_addr.s_addr = packet.source_ip;
#endif
        try {
            processPacketImmediatelly(addr,packet.len,packet.content);
        }
        catch(string& error)
	    {
			std::ostringstream stream;
			stream<<error<<" ";
            stream<<"  from node with ip "<<inet_ntoa(*((in_addr*)&packet.source_ip));
            stream<<" "<<KadCrawl::KadUtil::getFullIpGeoInfoFromIP(packet.source_ip);
			KadLogger::Log(WARN_KAD_LOG,stream.str());
		}
		catch (std::exception& e)
		{
			KadLogger::Log(WARN_KAD_LOG,e.what());
		}
        it = bufferedList.erase(it);
    }
    list<large_packet> bufferedLargeList = this->ExtractBufferedLargePacketList();    
    std::ostringstream lstream;
    lstream<<"Total Packets in Large Packet buffer pool :"<<bufferedLargeList.size();
    KadLogger::Log(INFO_KAD_LOG,lstream.str());
    list<large_packet>::iterator it_large = bufferedLargeList.begin(); 
    for(;it_large!=bufferedLargeList.end();)
    {
        large_packet packet = *it_large;
        struct sockaddr_in addr;
    	addr.sin_family = AF_INET;
    	addr.sin_port = packet.source_port;
#ifdef WIN32
    	addr.sin_addr.S_un.S_addr = packet.source_ip;
#else
    	addr.sin_addr.s_addr = packet.source_ip;
#endif
        try {
            processPacketImmediatelly(addr,packet.len,packet.content);
        }
        catch(string& error)
	    {
			std::ostringstream stream;
			stream<<error<<" ";
            stream<<"  from node with ip "<<inet_ntoa(*((in_addr*)&packet.source_ip));
            stream<<" "<<KadCrawl::KadUtil::getFullIpGeoInfoFromIP(packet.source_ip);
			KadLogger::Log(WARN_KAD_LOG,stream.str());
		}
		catch (std::exception& e)
		{
			KadLogger::Log(WARN_KAD_LOG,e.what());
		}
        it_large = bufferedLargeList.erase(it_large);
    }
}
void KadScanner::processBufferedListAndUpdateMP()
{
    list<small_packet> bufferedList = this->ExtractBufferedPacketList();    
    vector<small_packet> packets;
    packets.insert(packets.end(),bufferedList.begin(),bufferedList.end());
    bufferedList.clear();
    std::ostringstream stream;
    stream<<"Total Packets in buffer pool :"<<packets.size();
    KadLogger::Log(INFO_KAD_LOG,stream.str());
    #pragma omp parallel for
    for(int i=0;i<(int)packets.size();i++)
    {
        small_packet& packet = packets[i];
        struct sockaddr_in addr;
    	addr.sin_family = AF_INET;
    	addr.sin_port = packet.source_port;
#ifdef WIN32
    	addr.sin_addr.S_un.S_addr = packet.source_ip;
#else
    	addr.sin_addr.s_addr = packet.source_ip;
#endif
        try {
            processPacketImmediatelly(addr,packet.len,packet.content);
        }
        catch(string& error)
	    {
			std::ostringstream stream;
			stream<<error<<" ";
            stream<<"  from node with ip "<<inet_ntoa(*((in_addr*)&packet.source_ip));
            stream<<" "<<KadCrawl::KadUtil::getFullIpGeoInfoFromIP(packet.source_ip);
			KadLogger::Log(WARN_KAD_LOG,stream.str());
		}
		catch (std::exception& e)
		{
			KadLogger::Log(WARN_KAD_LOG,e.what());
		}
    }
}
void KadScanner::processBuffer()
{
    if(!processImmediatelly)
    {
        processBufferedListAndUpdate();
    }
}
void KadScanner::updateSendQueueByList()
{
	using namespace boost::posix_time;
	ptime program_start_time = second_clock::local_time();
    std::ostringstream stream;
    stream<<"Incoming peer count this round :";
    stream<<getIncomingPeerCount()<<endl;
    stream<<"Start to update send queue, discovered raw node list size :";

    boost::mutex::scoped_lock lock(nodeListLock);
    stream<<discoveredNodeList.size()<<endl;
	KadUtil::removeDuplicates(discoveredNodeList);
	list<KadNode> differenceSet;
	set_difference(discoveredNodeList.begin(),discoveredNodeList.end(),nodeList.begin(),nodeList.end(),inserter(differenceSet,differenceSet.begin()));
    discoveredNodeList.clear();
    lock.unlock();

    stream<<"Already collected node list size : ";
    stream<<nodeList.size()<<endl;
    KadLogger::Log(INFO_KAD_LOG,stream.str());

    unsigned long previous_size = nodeList.size();
	nodeList.insert(nodeList.end(),differenceSet.begin(),differenceSet.end());

	KadUtil::removeDuplicates(nodeList);
	sendRequestList.clear();
	if(!differenceSet.empty())
	{
		sendRequestList.insert(sendRequestList.begin(),differenceSet.begin(),differenceSet.end());
	}
    std::ostringstream estream;
    estream<<"sendRequest peer count next round :";
    estream<<sendRequestList.size()<<endl;
    estream<<"newly added node list size : ";
    estream<<nodeList.size()-previous_size<<endl;
    estream<<"current node list size :";
    estream<<nodeList.size()<<endl;
    KadLogger::Log(INFO_KAD_LOG,estream.str());

	ptime program_end_time = second_clock::local_time();
    time_duration time_duration = program_end_time - program_start_time;
    DEBUG_PRINT2("update queue time elapsed %s\n",to_simple_string(time_duration).c_str());
}
void KadScanner::updateSendQueueByHashTable()
{
	using namespace boost::posix_time;
	ptime program_start_time = second_clock::local_time();
    std::ostringstream stream;
    stream<<"Incoming peer count this round :";
    stream<<getIncomingPeerCount()<<endl;
    stream<<"Already collected node list size : ";
    boost::mutex::scoped_lock lock(nodeListLock);
    stream<<nodesMap.size()<<endl;
    sendRequestList.clear();
    HashedNodeMap::iterator it = nodesMap.begin(); 
    while(it != nodesMap.end())
    {
        KadNode& node = it->second;
        if(node.verified == false)
        {
            sendRequestList.push_back(node);
            node.verified = true;
        }
        it++;
    }
    lock.unlock();
    stream<<"the number of nodes to query in the next round "<<sendRequestList.size()<<endl;

    KadLogger::Log(INFO_KAD_LOG,stream.str());
	ptime program_end_time = second_clock::local_time();
    time_duration time_duration = program_end_time - program_start_time;
    DEBUG_PRINT2("update queue time elapsed %s\n",to_simple_string(time_duration).c_str());
}
/**
 * @brief set the next sending queue with nodes in newly discovered list which has not been contacted previously in nodelist
 */
void KadScanner::updateSendQueue()
{
    if(useHashTable)
        updateSendQueueByHashTable();
    else
        updateSendQueueByList();
}
list<KadNode> KadScanner::GetNewlyDiscoveredNodeList()
{
	boost::mutex::scoped_lock lock(nodeListLock);
    return discoveredNodeList;
}

bool KadScanner::registerKadMessageHandler(unsigned char opcode,KADEMLIA2_Handler handler)
{
	handlersMap[opcode].push_back(handler);
	return true;
}

void KadScanner::AddNodesFromSqlite(string db_path)
{
	DatabaseLogger db_logger;
	db_logger.init(db_path);
	list<KadNode> nodes = db_logger.LoadNodesDataFromFile();
	boost::mutex::scoped_lock lock(nodeListLock);
	nodeList.insert(nodeList.end(),nodes.begin(),nodes.end());
	db_logger.destroy();
	KadUtil::removeDuplicates(nodeList);
}

void KadScanner::InsertNode(KadNode node)
{
	nodeList.push_front(node);
    sendRequestList.push_front(node);
}

void KadScanner::setSearchResultType(SEARCH_RESULT_TYPE sType)
{
	this->searchResultType = sType;
}

unsigned int KadScanner::removeDuplicates()
{
	boost::mutex::scoped_lock lock(fileListLock);
	KadUtil::removeDuplicates(fileList);
	for(list<KadSharedFile>::iterator it=fileList.begin();it!=fileList.end();it++)
	{
		KadSharedFile& sFile = *it;
		sFile.removeDuplicates();
	}
	lock.unlock();
	return KadUtil::removeDuplicates(nodeList);
}

void KadScanner::resetAllToInitialState()
{
    boost::mutex::scoped_lock(this->nodeListLock);
    nodeList = bootstrapNodeList;
    sendRequestList = nodeList;
    discoveredNodeList.clear();
    activeKadNodeList.clear();
    tempKadNodeList.clear();
    respondingNodeList.clear();
}
void KadScanner::resetSendQueue()
{
	sendRequestList.clear();
	//sendRequestList.insert(sendRequestList.begin(),nodeList.begin(),nodeList.end());
	sendRequestList.insert(sendRequestList.begin(),bootstrapNodeList.begin(),bootstrapNodeList.end());
	nodeList.sort(KadCrawl::compareByKadIP);
	unsigned int limit=10000;
	unsigned int count=0;
	for(list<KadNode>::iterator it = nodeList.begin();it!=nodeList.end();it++)
	{
		KadNode tnode = *it;
		if(tnode.parentIpAddr != 0)
		{
			tnode.ipNetOrder = tnode.parentIpAddr;
			std::pair<list<KadNode>::iterator,list<KadNode>::iterator> matched_pair = equal_range(nodeList.begin(),nodeList.end(),tnode,KadCrawl::compareByKadIP);
			if(matched_pair.first!=nodeList.end())
			{
				list<KadNode>::iterator it_match = matched_pair.first;
				
				while(it_match != matched_pair.second)
				{
					KadNode& node = *it_match;
					if(node.ipNetOrder == tnode.ipNetOrder)
					{
						sendRequestList.push_back(node);
					}
					it_match++;
				}
				if(it_match == matched_pair.second)
				{
					KadNode& node = *it_match;
					if(node.ipNetOrder == tnode.ipNetOrder)
					{
						sendRequestList.push_back(node);
					}
				}
			}
		}
	}
	removeDuplicates();
}

bool operator== (const KadNode& node,const unsigned long addr)
{
	return node.ipNetOrder == addr;
}

class kad_label_writer{
public:
	kad_label_writer(Graph& _g):g(_g){}
	void operator()(std::ostream& out,const Vertex& v) const {

		//out << "[label=\"" << node->ipNetOrder << "\"]";
		nodeValueType node;
		NameMap map = get(&VertexProperties::node,g);

		if(v == 0)
			return;
		
		node = get(map,v);
		KadNode* nodep = get(map,v);
		if(node == 0)
			return;
		out << "[label=\"" << node->ipNetOrder << "\"]";
		
		
	}
private:
	Graph& g;
};

void KadScanner::BuildGraph()
{
	removeDuplicates();

	Graph g(nodeList.size());

	vector<KadNode> nodeVector;
	list<KadNode>::iterator it_cp = nodeList.begin();
	for(;it_cp!=nodeList.end();it_cp++)
	{	
		nodeVector.push_back(*it_cp);
	}

	vector<KadNode>::iterator startIt = nodeVector.begin();
	for(;startIt != nodeVector.end();startIt++)
	{
		int index = distance(nodeVector.begin(),startIt);
		int aindex = startIt - nodeVector.begin();
		DEBUG_PRINT2("%d ",index);
	}
	
	NameMap node_name = get(&VertexProperties::node,g);

	list<Edge>::iterator it = edgeList.begin();
	unsigned int count=0;
	for(;it!=edgeList.end();it++)
	{
		Edge& edge = *it;
		unsigned long src_addr = edge.first;
		unsigned long dst_addr = edge.second;

		vector<KadNode>::iterator foundSrcIt = find(nodeVector.begin(),nodeVector.end(),src_addr);
		vector<KadNode>::iterator foundDstIt = find(nodeVector.begin(),nodeVector.end(),dst_addr);

		if(foundSrcIt == nodeVector.end() || foundDstIt == nodeVector.end())
		{
			DEBUG_PRINT1("node not found\n");
			continue;
		}

		GraphEdge e;
		bool inserted;
		int srcIndex = foundSrcIt-nodeVector.begin();
		int dstIndex = foundDstIt-nodeVector.begin();
		boost::tie(e,inserted) = add_edge(foundSrcIt-nodeVector.begin(),foundDstIt-nodeVector.begin(),g);
		if(inserted)
		{
			Vertex u,v;
			u = source(e,g);
			put(node_name,u,&(*foundSrcIt));
			v = target(e,g);
			put(node_name,v,&(*foundDstIt));
			count++;

			KadNode* nodeA = get(node_name,u);
			KadNode* nodeB = get(node_name,v);
		}
	}

	//NameMap name_map = get(vertex_name,g);
	ofstream outfs("graph.dot");

	kad_label_writer lw(g);

	//print_graph(g,name_map);
	write_graphviz(outfs,g,lw);

	outfs.close();
}

unsigned long KadScanner::getIncomingPeerCount()
{
    return incomingPeerCount;
}
list<SimpleKadNode> KadScanner::getAbnormalLiveNodes()
{
    return unmatched_live_nodelist;
}
void KadScanner::resetIncomingPeerCount()
{
    incomingPeerCount=0;
}
void KadScanner::setInteractive(bool b_interactive)
{
    interactive = b_interactive;    
}
unsigned long KadScanner::GetQuerySentCount()   
{
    return query_sent_count;
}

