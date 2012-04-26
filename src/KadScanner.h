// KadScanner.h: interface for the KadScanner class.
//
//////////////////////////////////////////////////////////////////////
using namespace boost::interprocess;

typedef unsigned long (*KADEMLIA2_Handler)(unsigned long ip,unsigned char* data,unsigned long len);
typedef pair<uint32,uint32> Edge;
//typedef std::map<vector<unsigned char>,KadNode,bool(*)(vector<unsigned char>,vector<unsigned char>)> HashedNodeMap;
//typedef std::map<vector<unsigned char>,KadNode> HashedNodeMap;
typedef boost::unordered_map<vector<unsigned char>,KadNode> HashedNodeMap;

typedef struct _KadNodeWithWithoutPort
{
    unsigned long id[4];
    unsigned long ip;
}KadNodeWithoutPort;
typedef struct _KadNodeWithWithoutID
{
    unsigned long ip;
    unsigned short udp_port;
}KadNodeWithoutID;

//typedef boost::unordered_map<vector<unsigned char>,vector<vector<unsigned char> > > HashKeyConnector;
typedef multimap<vector<unsigned char>,vector<unsigned char> > HashKeyConnector;

typedef struct _shared_memory_buffer
{
   enum { NumItems = 10 };

   _shared_memory_buffer()
      : mutex(1), nempty(NumItems), nstored(0)
   {}
   //Semaphores to protect and synchronize access
   boost::interprocess::interprocess_semaphore
      mutex, nempty, nstored;

   //Items to fill
   int items[NumItems];
}shared_memory_buffer;

enum SEARCH_RESULT_TYPE
{
	SEARCH_FILE,
	SEARCH_KEYWORD,
	SEARCH_NOTES
};
#define SMALL_PACKET_LEN 600
typedef struct _small_packet
{
    unsigned char content[SMALL_PACKET_LEN];
    unsigned short len;
    unsigned short source_port;
    unsigned long source_ip;
	struct _small_packet& operator =(const struct _small_packet &other)
	{
		memset(content,0,SMALL_PACKET_LEN);
        memcpy(content,other.content,SMALL_PACKET_LEN);
        len = other.len;
        source_port = other.source_port;
        source_ip = other.source_ip;
		return *this;
	}
}small_packet;
#define LARGE_PACKET_LEN 2000
typedef struct _large_packet
{
    unsigned char content[LARGE_PACKET_LEN];
    unsigned short len;
    unsigned source_port;
    unsigned long source_ip;
    struct _large_packet& operator =(const struct _large_packet &other)
	{
		memset(content,0,LARGE_PACKET_LEN);
        memcpy(content,other.content,LARGE_PACKET_LEN);
        len = other.len;
        source_port = other.source_port;
        source_ip = other.source_ip;
		return *this;
	}
}large_packet;

/**
 * @brief for additional fix for elegance
 */
struct _super_large_packet:public _large_packet 
{
    unsigned char additional_content[LARGE_PACKET_LEN];
};
class KadScanner  
{
///////////////////////////////////////////////////////////
//Packet Process Handler
///////////////////////////////////////////////////////////
private:
	void Process_KADEMLIA2_BOOTSTRAP_RES(const BYTE* data,uint32 uLen,uint32 ip,uint16 uUDPPort,KadUDPKey key);
	void Process_KADEMLIA2_PING(const BYTE* data,uint32 uLen,uint32 ip, uint16 uUDPPort, KadUDPKey key);
	void Process_KADEMLIA2_PONG(const BYTE* data,uint32 uLen,uint32 ip, uint16 uUDPPort, KadUDPKey key);
	void Process_KADEMLIA2_RES(const BYTE* data,uint32 uLen,uint32 ip,uint16 uUDPPort,KadUDPKey key);
	void Process_KADEMLIA2_SEARCH_RES(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key);
	void Process_KADEMLIA_FINDBUDDY_RES(const BYTE *data,uint32 uLen,uint32 ip,uint16 uUDPPort,KadUDPKey key);
	void Process_KADEMLIA2_HELLO_RES(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key);

	void Process_KADEMLIA_FIREWALLED2_REQ(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key);
    void Process_KADEMLIA2_PUBLISH_KEY_REQ(const BYTE *data,uint32 uLen,uint32 ip,uint16 uUDPPort,KadUDPKey key);
	void Process_KADEMLIA2_REQ(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key);
	void Process_KADEMLIA2_HELLO_REQ(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key);
	void Process_KADEMLIA2_BOOTSTRAP_REQ(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key);

    // deprecated kad version 1
    void Process_KADEMLIA_REQ(const BYTE *data, uint32 uLen, uint32 ip, uint16 uUDPPort, KadUDPKey key);
    void Process_KADEMLIA_BOOTSTRAP_RES_DEPRECATED(const BYTE* data,uint32 uLen,uint32 ip,uint16 uUDPPort,KadUDPKey key);
    void Process_KADEMLIA_PUBLISH_KEY_REQ(const BYTE *data,uint32 uLen,uint32 ip,uint16 uUDPPort,KadUDPKey key);

	void Process_KADEMLIA_SEARCHRESULT_SOURCE(KadSharedFile& file,CUInt128 uAnswer,TagList* pTags,uint32 ip,uint16 udp_port);
	void Process_KADEMLIA_SEARCHRESULT_KEYWORD(KadSharedFile& kadFile,KadKeywordNode& kNode,CUInt128 uAnswer,TagList* pTags,uint32 ip,uint16 udp_port);
	void Process_KADEMLIA_SEARCHRESULT_NOTES(KadSharedFile& file,CUInt128 uAnswer,TagList* pTags,uint32 ip,uint16 udp_port);

	void processKadPackedPacket(BYTE* pBuffer,int nPacketLen,uint32 nReceiverVerifyKey,uint32 nSenderVerifyKey,uint32 addrULong,uint16 port);
	void processOriginalPacket(BYTE* data,uint32 dataLen,uint32 ipaddr,uint16 port,bool validReceiveKey,KadUDPKey senderUDPKey);

    // Latent Processing of Buffered Packets
    void processPacketImmediatelly(sockaddr_in &address,uint16 count,uint8 *data);
    void bufferIncomingPackets(sockaddr_in &address,uint16 count,uint8 *data);

    void processBufferedListAndUpdate();
    void processBufferedListAndUpdateMP();
public:
    void processPacket(sockaddr_in &address,uint16 count,uint8* data);
    void processBuffer();

///////////////////////////////////////////////////////////
// Send Packet Function
///////////////////////////////////////////////////////////
private:
	void sendPacket(uchar *pBuf,uint32 dataLen,uint32 uDestinationHost,uint16 uDestinationPort,KadUDPKey targetUDPKey, const CUInt128 *uCryptTargetID);
	void sendPacket(Packet* pPacket, uint32 uDestinationHost, uint16 uDestinationPort, KadUDPKey targetUDPKey, const CUInt128 *uCryptTargetID);
	void sendPacket(uchar* pBuf,uint32 dataLen,byte byOpcode,uint32 uDestinationHost,uint16 uDestinationPort,KadUDPKey targetUDPKey,const CUInt128* uCryptTargetID);

	int DecryptReceivedClient(BYTE* pbyBufIn, int nBufLen, BYTE** ppbyBufOut, uint32 dwIP, uint32* nReceiverVerifyKey, uint32* nSenderVerifyKey);
	int EncryptSendMsg(uchar** ppbyBuf,int nBufLen,const char* pachClientHashOrKadID,bool bKad,uint32 nReceiverVerifyKey,uint32 nSenderVerifyKey);

    AsioUDPServer* asioServer;
	AsioTCPServer* asioTcpServer;

    bool useHashTable;
public:
    void setAsioServer(AsioUDPServer* server);
	void setAsioTcpServer(AsioTCPServer* server);
    void setUseHashTable(bool useHashTable);
public:
    void sendNodeLookupReq(CUInt128& target,KadNode& node,uint8 requestCount);
	void sendKeywordLookupReq(string keyword,KadNode &node);
	void sendKeywordTargetLookupReq(string keyword,KadNode &node);
	void sendBootstrapReq(KadNode &node);
	void SendMyDetails(uint8 byOpcode,KadNode& node,bool requestAck,uint8 version);
    void SendDetailsWithIdentity(uint8 byOpcode,KadNode& node,KadNode& sybil_node,bool requestAck,uint8 version);
	void sendPingProbe(KadNode& node);
	void sendFindBuddyReq(KadNode& node);
	void sendStoreKeywordRequest(KadNode& node,string keyword);
	void sendSearchFileSourceRequest(KadSharedFile& file);
	void interactWithPeerForFileInfo(KadNode& node);
    
/////////////////////////////////////////////////////////////
// Common Functionality
/////////////////////////////////////////////////////////////
public:
	void saveNodesInfoToFile(string filepath,unsigned int version);
    void Calibrate();
	string DumpRoutingZoneInfo();
	string DumpNodesIPGeoInfo();
    void checkDuplicateMapItems(HashedNodeMap& map);
	
	bool registerKadMessageHandler(unsigned char opcode,KADEMLIA2_Handler handler);
   	list<KadSharedFile> GetSharedFileList();
	
	bool Init();
	void Destroy();
	
	string DumpNodesInfo();
	string DumpKadSharedFiles();
	int readKadNodesDataFile(string filepath);
	void InsertNode(KadNode node);
	void setToBootstrapNodes();
	void setToNearerNodesFromBootNodes(CUInt128 target_id,uint32 range);
	
	uint32 GetUDPVerifyKey(uint32 dwTargetIP);
	AsioTCPServer* getTcpEngine();
	AsioUDPServer* getUdpEngine();

	KadScanner();
	virtual ~KadScanner();

	vector<unsigned long> gradual_count;

////////////////////////////////////
//  node list of various type, should move to another elegant design style 
////////////////////////////////////
public:
	const list<KadNode>& GetNodeList();
    const HashedNodeMap& GetNodesMap();
    ULONG GetNodesSize();
	void clearList();
	list<KadNode> GetUnRequestedNodeList();
	list<KadNode> GetNonBootstrapNodes();
	list<KadNode> GetNewlyDiscoveredNodeList();
    list<SimpleKadNode> GetTempLiveNodes();	
    list<KadNode> GetActiveKadNode();
    list<KadNode> GetActiveRouteQueryNodeList();
    list<KadNode> GetActiveFirewallRequestNodeList();
    list<KadNode> GetActiveDeprecatedKadNodeList();
    const list<SimpleKadNode>& GetBootstrapRespondingKadNodeList();
    const list<KadNode>& GetCrawledSnapShot();
    unsigned long GetActiveUnknowNodeSize();
    unsigned long GetQuerySentCount();    
private:
    list<SimpleKadNode> unmatched_live_nodelist;
	boost::mutex nodeListLock;
//  node list of current pool
	list<KadNode> nodeList;
//  node list for bootstrapping
	list<KadNode> bootstrapNodeList;
//  temporary list of newly discovered
	list<KadNode> discoveredNodeList;
//  node list for next round request
	list<KadNode> sendRequestList; 
//  temp node list which responde to HelloReq
    list<SimpleKadNode> tempKadNodeList;
    boost::mutex tempNodeListLock;
//  node list who activelly send HelloReq
    list<KadNode> activeKadNodeList;
    boost::mutex activeKadNodeListLock;
//  node list who activelly send RouteReq
    list<KadNode> activeRouteQueryKadNodeList;
    boost::mutex activeRouteQueryKadNodeListLock;
//  node list who activelly send firewall req in the wake of RouteReq
    list<KadNode> activeFirewallReqNodeList;
    boost::mutex activeFirewallReqNodeListLock;
//  kad client communicated with us using obsolete protocol message
    list<KadNode> activeDeprecatedKadNodeList;
    boost::mutex activeDeprecatedKadNodeListLock;
//  list of sharedfile 
    boost::mutex fileListLock;
	list<KadSharedFile> fileList;
//  list of nodes who responde to our query
    list<SimpleKadNode> respondingNodeList; 
//  hashmap of all nodes  
    HashedNodeMap nodesMap;
/////////////////////////////////////
	RoutingZone *routingZone;
	list<Edge> edgeList;

	map<unsigned char,vector<KADEMLIA2_Handler> >handlersMap;
		
	SEARCH_RESULT_TYPE searchResultType;
    unsigned long incomingPeerCount;

    unsigned long query_sent_count;

    bool interactive;
    unsigned long active_unmatched_node_size;
public:
    /**
     * @brief remove duplicate counts of kad node
     *
     * @return the size of nodes which are duplicates
     */
	unsigned int removeDuplicates();

    /**
     * @brief set all nodelist data to initial state
     */
    void resetAllToInitialState();
    
    /**
     * @brief insert node into list while processing query packets
     *
     * @Param node peer info to insert
     */
    void putNodeToTempList(KadNode node);
    /**
     * @brief insert node to alive state
     *
     * @Param target_node node of which we would change state
     */
    void putKadNodeToAliveState(SimpleKadNode target_node);
    
    /**
     * @brief process unmatched node list
     */
    void processUnmatchedNodeList();
    /**
     * @brief process nodes who respond to our ping query
     */
    list<KadNode> processPingAliveNodes();
    /**
     * @brief set states of all live nodes in the nodesMap
     */
    void setStateOfLiveNodes();
    /**
     * @brief set states of all nodes in list and map to inactive
     */
    void setAllNodesToInactive();
    /**
     * @brief update send queue after each round of query
     */
	void updateSendQueue();
    /**
     * @brief update send queue through reconstructing the node list
     */
    void updateSendQueueByList();
    /*
     * @brief update send queue through reconstructing the node hashtable
     */
    void updateSendQueueByHashTable();
    /**
     * @brief fill the send queue with live nodes in the full node list(live nodes are those give out response to us)
     */
	void resetSendQueue();
    /**
     * @brief build graph for the nodelist
     */
	void BuildGraph();
    /**
     * @brief add nodes contained in the specified sqlite database
     *
     * @Param db_path the sqlite3 database file path which contains kad nodes info
     */
	void AddNodesFromSqlite(string db_path);

    /**
     * @brief set search result type which used in file searches
     *
     * @Param type search result type
     */
	void setSearchResultType(SEARCH_RESULT_TYPE type);
    /**
     * @brief current count of peers which send message to us
     *
     * @return count of incoming peers
     */
    unsigned long getIncomingPeerCount();
    /**
     * @brief reset the count of peers which contacts us to zero
     */
    void resetIncomingPeerCount();
    /**
     * @brief extract the list of small_packet from buffer
     *
     * @return list of packets in the buffer
     */
    list<small_packet> ExtractBufferedPacketList();
    /**
     * @brief extract the list of large_packet from buffer
     *
     * @return list of larget packets in the buffer
     */
    list<large_packet> ExtractBufferedLargePacketList();
    /**
     * @brief flags indicate whether to process the packet when it arrives or wait for further command
     *
     * @Param isImmediate flags,true to process when packet arrives,false otherwise
     */
    void setProcessImmediatelly(bool isImmediate);
    /**
     * @brief set interactive mode
     *
     * @Param b_interactive whether be intrusive in behavior
     */
    void setInteractive(bool b_interactive);

    /**
     * @brief get the abnormal nodes which does not conform to the protocol specification
     *
     * @return abnormal live nodes
     */
    list<SimpleKadNode> getAbnormalLiveNodes();

    list<small_packet> bufferedPacketList;
    list<large_packet> bufferedLargePacketList;
    bool processImmediatelly;
    boost::mutex processImmediatellyLock;
};

