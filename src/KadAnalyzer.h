#pragma once

typedef map<unsigned long,unsigned long > countKadNodeMap;
typedef map<CUInt128,vector<KadNode> > countKadNodeIDMap;
typedef std::map<vector<char>,SessionKadNode> SessionNodeMap;
typedef std::map<vector<char>,unsigned long> CompactSessionNodeMap;
typedef std::map<vector<char>,unsigned long> TemporalSessionNodeMap;
// netmask map to (ip to size) version 1
// netmask map to (ip to (live dead unmatched))) up to date version
typedef std::map<unsigned long,vector<unsigned long> > IPCountMap;
typedef std::map<unsigned long,IPCountMap> AllIPCountMap;
typedef pair<unsigned int,boost::tuple<unsigned int,unsigned int,unsigned int> > UDPPortResultType;
typedef vector<UDPPortResultType> UDPPortCountMap;

typedef vector<pair<CUInt128,vector<KadNode> > > IDCountVecType;
typedef std::map<string,vector<unsigned long> > IDString2StateCountMap;

typedef vector<pair<unsigned long,unsigned long> > IPCountVecType;
typedef std::map<unsigned long,vector<unsigned long> > IP2VersionCount;
typedef std::map<unsigned long,vector<unsigned long> > IP2StateCount;
class KadAnalyzer
{
public:
	KadAnalyzer(void);
	~KadAnalyzer(void);

    void init();

    /**
     * @brief analyze data about the 5 minutes session logs(current nodes snapshot) of single emule client 
     *
     * @Param dir_path all the files with specified pattern would be treated as the session log of kad client and then analyzed
     *                 interaction of these sessions would be written to liveNodes.dat
     *                 union of these sessions would be written to unionNodes.dat
     */
	void AnalyzeEmuleKadNodeSessionLogInDir(string dir_path);
    void AnalyzeEmuleKadNodeSessionLogInDir(std::vector<string> fileList);
    /**
     * @brief analyze single file of kad nodes data
     *
     * @Param file_path path of target file to analyze
     */
	void AnalyzeEmuleKadNodesFile(string file_path);
    /**
     * @brief analyze kad nodes in specific zone
     *
     * @Param file_path path of specified kad node file
     * @Param zone_index target zone index of kad node file
     */
    void AnalyzeEmuleKadNodesFileInSpecifiedZone(string file_path,unsigned int zone_index);
    /**
     * @brief analyze kad nodes in specific country
     *
     * @Param file_path path of specified kad node file
     * @Param country target country name
     */
    void AnalyzeEmuleKadNodesFileInSpecifiedCountry(string file_path,string country);
    /**
     * @brief analyze kad nodes with specified version
     *
     * @Param file_path path of specified kad node file
     * @Param version_param version number
     */
    void AnalyzeEmuleKadNodesFileWithSpecifiedVersion(string file_path,unsigned int version_param);
    
    /**
     * @brief analyze specified kad node list
     *
     * @Param nodeList node list to analyze
     *
     * @return log of the analysis
     */
    string AnalyzeEmuleKadNodes(list<KadNode>& nodeList);

    /**
     * @brief analyze simple kad nodes
     *
     * @Param nodeList list of simplified kad nodes
     *
     * @return analysis output
     */
    string AnalyzeSimpleKadNodes(list<SimpleKadNode>& nodeList);
    /**
     * @brief Analyze node file of specific kad zone
     *
     * @Param dir_path 
     */
	void AnalyzeEmuleKadZoneDir(string dir_path);
    
    /**
     * @brief count the size of live kad nodes from helloRequest result
     *
     * @Param nodeList full list of kad nodes
     * @Param tempNodeList node list who responde to helloRequest
     *
     * @return output log of the count
     */
	string AnalyzeLiveKadNodes(list<KadNode>& nodeList,list<SimpleKadNode>& tempNodeList);
    string AnalyzeKadActiveCount(const list<KadNode>& nodeList_param,unsigned int maximum_show_size);
    /**
     * @brief count the type statistics of incoming messages
     *
     * @Param type incoming message type
     */
    void countIncomingMessageType(unsigned char type);
    /**
     * @brief get ip history statistics of snapshots of kad network
     *
     * @Param matchedFiles file to analyze
     * @Param prefix_begin begin of prefix which is between 1 and 32
     * @Param prefix_end end of prefix
     *
     * @return analysis output in the form of string
     */
    string getIPHistoryStatisticsGeneric(vector<boost::tuple<string,time_t> > matchedFiles,unsigned long prefix_begin,unsigned long prefix_end,const KadCrawl::KadFilter& pass_filter,const KadCrawl::KadFilter& block_filter);

    /**
     * @brief show the type statistics
     */
    string showTypesCountOfIncomingMessages();
    /**
     * @brief load ip history map from file
     *
     * @Param filename filename of ip history file
     *
     * @return ip history brief information
     */
    string loadIPHistoryStatisticsFromFile(string filename);
    void AnalyzeKadZoneNodesList(const list<KadNode>& nodeList,unsigned char zone_index);
    void AppendNodeListSnapshot(const list<KadNode>& nodeList);
    string AnalyzeNodeListSnapShotsAsZoneCrawl(unsigned char zone_index);
    string AnalyzeCollectionOfKadNodeList(vector<list<KadNode> >&  nodeListVector);
    string AnalyzeRepititionOfKadNodeListByPathList(vector<string> path_list);
    string AnalyzeIPRepititionOfKadNodeListByPathList(vector<string> path_list);
    string CountVersionOfNodes(const list<KadNode>& nodeList);
    string CountEightBitZoneStatOfNodes(const list<KadNode>& nodeList);
    void countCNetStatistics(string path);
    string CountUDPPortOfNodes(const list<KadNode>& nodeList,unsigned int show_count);
    list<KadNode> findNodesByIP(const list<KadNode>& nodeList,string ip,unsigned int mask);
    list<KadNode> findNodesByIP(const list<KadNode>& nodeList,unsigned long ip,unsigned int netmask);
    list<KadNode> findNodesByIPInDirectory(string directory,string file_filter,string ip,unsigned int netmask,unsigned int elapsed_minutes);
    SessionNodeMap getLiveSessionStatistics(string directory,string prefix_filter,unsigned long maximum_files,unsigned int elapsed_minutes);
    CompactSessionNodeMap getLiveSessionStatisticsCompactWithOptionalCountryCode(string directory,string prefix_filter,unsigned long maximum_files,unsigned int elapsed_minutes,string country_code);
    SessionNodeMap getLiveSessionStatisticsGeneric(vector<boost::tuple<string,time_t> > matchedFiles);
    list<KadNode> findNodesByIPInDirectoryByQuantile(string directory,string prefix_filter,string ip,unsigned int netmask,unsigned int quantile_begin_int,unsigned int quantile_end_int,unsigned int maximum_files);
    string dumpSessionStatistics(SessionNodeMap& map,unsigned long maximum_files);
    string dumpCompactSessionStatistics(CompactSessionNodeMap& map);
    bool checkFilter(const KadNode & node,const KadCrawl::KadFilter & filter);
private:
	void compareKadPeers(std::vector<string>& seedFileList);
	void compareKadPeersDir(const string& dirPath);

    /**
     * @brief get state info of all distinct ids in specific node list file
     *
     * @Param nodeList_param target node list to analyze
     *
     * @return state info of all ids
     */
    IDString2StateCountMap getID2StateMap(const list<KadNode>& nodeList_param);
    /**
     * @brief get state info of all ips in specific node list file
     *
     * @Param nodeList_param target node list to analyze
     *
     * @return state info of all ips
     */
    IP2StateCount getIP2StateMap(const list<KadNode>& nodeList_param);
    /**
     * @brief get version info of all ips in specific node list file
     *
     * @Param nodeList_param target node list
     *
     * @return version info of all ips
     */
    IP2VersionCount getIP2VersionMap(const list<KadNode>& nodeList_param);
    /**
     * @brief get ip statistic of nodelist 
     *
     * @Param nodeList target nodelist 
     *
     * @return string representation of resulting statistics
     */
    string getIPStatisticMap(const list<KadNode>& nodeList);
    /**
     * @brief get ip statistic of nodelist 
     *
     * @Param nodeList target nodelist 
     *
     * @return IPCountVecType representation of resulting statistics
     */
    IPCountVecType getIPStatisticMapGeneric(const list<KadNode>& nodeList_param);
    /**
     * @brief get id statistics of nodelist
     *
     * @Param nodeList target nodelist 
     *
     * @return string representation of resulting statistics
     */
    string getIDStatisticMap(const list<KadNode>& nodeList);
    /**
     * @brief get id statistics of nodelist
     *
     * @Param nodeList target nodelist 
     *
     * @return IDCountVecType representation of resulting statistics
     */
    IDCountVecType getIDStatisticMapGeneric(const list<KadNode>& nodeList_param);
    /**
     * @brief get statistics of nodelist by ip prefix
     *
     * @Param nodeList target nodelist
     * @Param prefix prefix for statistics
     *
     * @return count of address with specified prefix
     */
    unsigned long getStatisticsByIPPrefix(const list<KadNode>& nodeList,unsigned long prefix);

    /**
     * @brief 
     *
     * @Param nodeList simple format of nodelist
     * @Param prefix netmask for the ip of kad node
     *
     * @return total size of distinct custom ip
     */
    unsigned long getStatisticsByIPPrefix(const list<SimpleKadNode>& nodeList,unsigned long prefix);

    vector<list<KadNode> > nodeListSnapList;

    /**
     * @brief type count of incoming messages
     */
    map<unsigned char,unsigned long> messageIncomingMap;
    map<unsigned char,string> types_constants;
    map<unsigned long,unsigned long> netmask_prefix_map;
    AllIPCountMap ip_count_map;
};
