#pragma once

namespace KadCrawl
{
    class KadFilter
    {
    public:
        KadNode node;
        bool check_zone_id;
        bool check_ip;
        bool check_udp_port;
        bool check_version;
        bool check_tcp_port;
        bool check_kad_state;
        bool check_flag;
        KadFilter(){
            check_zone_id=false;
            check_ip=false;
            check_udp_port=false;
            check_version=false;
            check_tcp_port=false;
            check_kad_state=false;
            check_flag=false;
        }
    };
	class findKadNodeByIP{
	public:
		findKadNodeByIP(unsigned long _ip):ip(_ip){}
		bool operator() (const KadNode& node)
		{
			return node.ipNetOrder == ip;
		}
	private:
		const unsigned long ip;
	};

	class findKadNodeByID{
	public:
		findKadNodeByID(CUInt128 _id):id(_id){}
		bool operator() (const KadNode& node)
		{
			return node.kad_id == id;
		}
	private:
		const CUInt128 id;
	};

	class countByIDByte{
	public:
		countByIDByte(unsigned char _byteChunk):byteChunk(_byteChunk){}
		bool operator() (const KadNode& node)
		{
			return node.kad_id.GetByteChunk(0) == byteChunk;
		}
	private:
		unsigned char byteChunk;
	};
	class countByIDByteAndLiveState{
	public:
		countByIDByteAndLiveState(unsigned char _byteChunk):byteChunk(_byteChunk){}
		bool operator() (const KadNode& node)
		{
			return node.kad_id.GetByteChunk(0) == byteChunk && node.state == KAD_ALIVE;
		}
	private:
		unsigned char byteChunk;
	};
	class countByIDByteAndUnmatchedState{
	public:
		countByIDByteAndUnmatchedState(unsigned char _byteChunk):byteChunk(_byteChunk){}
		bool operator() (const KadNode& node)
		{
			return node.kad_id.GetByteChunk(0) == byteChunk && node.state == KAD_UNMATCHED;
		}
	private:
		unsigned char byteChunk;
	};
	class countVersion{
	public:
		countVersion(unsigned char _byteChunk):byteChunk(_byteChunk){}
		bool operator() (const KadNode& node)
		{
			return node.version == byteChunk;
		}
	private:
		unsigned char byteChunk;
	};
	class countVersionAndLiveState{
	public:
		countVersionAndLiveState(unsigned char _byteChunk):byteChunk(_byteChunk){}
		bool operator() (const KadNode& node)
		{
			return node.version == byteChunk && node.state == KAD_ALIVE;
		}
	private:
		unsigned char byteChunk;
	};
	class countVersionAndUnmatchedState{
	public:
		countVersionAndUnmatchedState(unsigned char _byteChunk):byteChunk(_byteChunk){}
		bool operator() (const KadNode& node)
		{
			return node.version == byteChunk && node.state == KAD_UNMATCHED;
		}
	private:
		unsigned char byteChunk;
	};
	class countUDPPort{
	public:
		countUDPPort(unsigned short _port):port(_port){}
		bool operator() (const KadNode& node)
		{
			return node.udp_port == port;
		}
	private:
		unsigned short port;
	};
	class countUDPPortWithLiveState{
	public:
		countUDPPortWithLiveState(unsigned short _port):port(_port){}
		bool operator() (const KadNode& node)
		{
			return node.udp_port == port && node.state == KAD_ALIVE;
		}
	private:
		unsigned short port;
	};
	class countUDPPortWithUnmatchedState{
	public:
		countUDPPortWithUnmatchedState(unsigned short _port):port(_port){}
		bool operator() (const KadNode& node)
		{
			return node.udp_port == port && node.state == KAD_UNMATCHED;
		}
	private:
		unsigned short port;
	};
	bool compareByKadID(SimpleKadNode aNode,SimpleKadNode bNode);
	bool compareByKadIP(SimpleKadNode aNode,SimpleKadNode bNode);
    bool compareByKadSurvivalCount(KadNode& nodeA,KadNode& nodeB);

	bool equalByKadIP(SimpleKadNode aNode,SimpleKadNode bNode);
	bool equalByKadID(SimpleKadNode aNode,SimpleKadNode bNode);

	class KadUtil
	{
	public:
		KadUtil(void);
		~KadUtil(void);

		static CUInt128 kad_id;
		static CUInt128 client_hash;
        static unsigned short udp_port;
		static uint32 udpVerifyKey;
        static string log_directory;

		static void Init();
		static void Destroy();
        static void setRandomKadID();
        static void setIDByKeyword(string keyword);

        template <class T>
            static unsigned int removeDuplicates(list<T>& nodeList)
            {
                return removeDuplicates(nodeList,std::less<T>(),std::equal_to<T>());
            }
        template <class T>
            static list<T> extractDuplicates(list<T>& nodeList)
            {
                return extractDuplicates(nodeList,std::less<T>(),std::equal_to<T>());
            }

        template <class T,class CompareA,class CompareB>
            static unsigned int removeDuplicates(list<T>& nodeList,CompareA compareLess,CompareB compareEqual)
            {
                nodeList.sort(compareLess);
                unsigned long erasedNum = nodeList.size();
                nodeList.erase(unique(nodeList.begin(),nodeList.end(),compareEqual),nodeList.end());
                erasedNum -= nodeList.size();
                return erasedNum;
            }
        template <class T,class CompareA,class CompareB>
            static list<T> extractDuplicates(list<T>& nodeList,CompareA compareLess,CompareB compareEqual)
            {
                list<T> localList = nodeList;
                list<T> resultList;
                localList.sort(compareLess);
                resultList.insert(resultList.end(),unique(localList.begin(),localList.end(),compareEqual),localList.end());
                return resultList;
            }
        template <class T,class CompareA>
            static list<T> extractSubList(list<T>& nodeList,CompareA compareLess,unsigned int size)
            {
                list<T> localList = nodeList;
                list<T> resultList;
                localList.sort(compareLess);
                if(size < localList.size())        
                {
                    for(unsigned int i=0;i<size;i++)
                    {
                        resultList.push_back(localList.front());
                        localList.pop_front();
                    }
                }
                else
                    resultList = localList;
                return resultList;
            }
        template <typename ClassSerialize>
            static int SaveObject(const string filename,const ClassSerialize &c) 
            {
                ofstream f(filename.c_str(),ios::binary);
                if(f.fail())
                    return -1;
                boost::archive::binary_oarchive oa(f);
                oa<<c;
                return 0;
            }
        template <typename ClassSerialize>
            static int LoadObject(const string filename,ClassSerialize &c) 
            {
                ifstream f(filename.c_str(),ios::binary);
                if(f.fail())
                    return -1;
                boost::archive::binary_iarchive oa(f);
                oa>>c;
                return 0;
            }
              
        static list<SimpleKadNode> convertToSimpleNode(const list<KadNode>& nodeList);
        static list<KadNode> expandToFullKadNode(const list<SimpleKadNode>& nodeList);
        static list<SearchKadNode> convertToSearchKadNode(const list<KadNode>& nodeList);

		static CUInt128 getInt128FromString(string keyword);

		unsigned int removeDuplicatesSustainGraphRelation(list<KadNode>& nodeList);
       	static KadNode* FindKadNodeByID(ContactList& nodeList,CUInt128 uID);
		static KadNode* FindKadNodeByIP(ContactList& nodeList,unsigned long uIP );
		static list<KadNode> GetNeighboringNodes(list<KadNode>& nodeList,CUInt128 target_id,unsigned long range);
private:
        static int readKadNodesDataToListEx(string path,list<KadNode>& nodeList,unsigned int count,unsigned int version);
        static int readKadNodesDataToListOld(string path,list<KadNode>& nodeList,unsigned int count,unsigned int version);
public:
		static int readKadNodesDataToList(string filepath,list<KadNode>& nodeList);
        static int readKadNodesDataToListWithCountrySpecified(string filepath,list<KadNode>& nodeList,string country_code);
		static void saveNodesInfoToFile(string filepath,unsigned int version,const list<KadNode>& nodeList);
        static void saveNodesInfoToFile(string filepath,unsigned int version,const list<SimpleKadNode>& nodeList);
        static void saveNodesInfoToDefaultPath(unsigned version,const list<KadNode>& nodeList);
        static void saveZoneNodesInfoToDefaultPath(unsigned version,const list<KadNode>& nodeList,unsigned char zone_index);
        static void saveNodesInfoToDefaultPathWithPrefix(string prefix,unsigned version,const list<KadNode>& nodeList);
        static void saveIPOfNodeListToPath(string prefix,list<SimpleKadNode> nodeList);
		static map<string,unsigned long> GetGeoInfoFromNodeList(const list<KadNode>& nodeList);
        static boost::tuple<map<string,unsigned long>,map<string,unsigned long>,map<string,unsigned long> > GetGeoInfoAndLiveStateFromNodeList(const list<KadNode>& nodeList);
        static map<string,unsigned long> GetGeoInfoFromNodeListWithMask(const list<SimpleKadNode>& nodeList,unsigned long mask);
        static map<string,unsigned long> GetAsInfoFromNodeList(const list<KadNode>& nodeList);
		static string getCountryNameFromIP(unsigned long ip);
        static string getCountryCodeFromIP(unsigned long ip);
        static string getASNumFromIP(unsigned long ip);
        static string getQQIpInfoFromIP(unsigned long ip);
        static string getGeoCityInfoFromIP(unsigned long ip);
        static string getFullIpGeoInfoFromIP(unsigned long ip);

        static vector<boost::tuple<string,time_t> > getFileListOfDirectoryInternal(string dir_path,string regex_filter,unsigned long maximum_returned,unsigned long minutesLimit=-1);
        static vector<string> getFileListOfDirectory(string regex_filter,string dir_path,unsigned long maximum_returned=65535);
        static vector<boost::tuple<string,time_t> > getFileListOfDirectoryByTimeQuantile(string dir_path,string regex_filter,unsigned long begin_quantile_long,unsigned int end_quantile_long,unsigned long maximum_returned);
        static vector<string> getFileListOfDirectoryTimeLimited(string dir_path,string regex_filter,unsigned long maximum_returned=65535,unsigned long minutesLimit=0);

		static string DumpNodesInfo(ContactList nodeList);
		static bool fromNodeFileToSqlite(string nodeFilePath,string sqlitePath);

		static string showDuplicateCountDuringSearch();
		static string DumpNodesIPGeoInfo(ContactList nodeList);
        static string DumpNodesIPAsInfo(ContactList nodeList);
        static void writeKadNodesToCSV(const list<KadNode>& nodeList,string savePath);
        static bool fromNodeFileToCsv(string nodeFilePath,string sqlitePath);

        static unsigned long getNetmaskLongFromOrder(unsigned int netmask_order);
        inline static unsigned long convertIPtoMaskedIP(unsigned long ip,unsigned long mask)
        {
            return htonl(ntohl(ip) & mask);    
        }
        inline static unsigned long netmaskIPLong(unsigned long ip,unsigned int netmask_order)
        {
            unsigned long netmask = getNetmaskLongFromOrder(netmask_order);
            return htonl(ntohl(ip) & netmask);
        }

        static void convertIPWithNetmask(list<KadNode>& nodeList,unsigned int netmask_order);
        static void convertIPWithNetmask(list<SearchKadNode>& nodeList,unsigned int netmask_order);
        static list<KadNode> extractRandomSetFromNodeList(list<KadNode> nodeList,unsigned long size); 
        static list<KadNode> extractLiveNodesFromNodeList(list<KadNode> nodeList);
        static list<KadNode> extractNodesFromNodeListByVersion(list<KadNode> nodeList,unsigned short version); 
        static list<KadNode> extractUnmatchedNodesFromNodeList(list<KadNode> nodeList); 
        static list<KadNode> extractNodesOfSpecificCountryFromNodeList(list<KadNode> nodeList,string country_code);
        
        static bool checkFilter(const KadNode& node,const KadFilter& filter);
        static bool checkOrBlockFilter(const KadNode& node,const KadFilter& filter);
private:
        
        static void saveNodesInfoToFileDetail(string filepath,unsigned int version,const list<KadNode>& nodeList);
        static void saveNodesInfoToFileLegacy(string filepath,unsigned int version,const list<KadNode>& nodeList);

		static GeoIP * gi;
        static GeoIP * gi_as;
        static GeoIP * gi_city;
        static CIpInfo* qqIpEngine;
		static vector<unsigned long> duplicateCountVector;
	};

	class checkInSame8bitZone
	{
	public:
		checkInSame8bitZone(const CUInt128 & m_id):id(m_id){};

		bool operator()(const KadNode& node)
		{
			//return id.GetByteChunk(0)==comp_id.GetByteChunk(0);
			unsigned char byte = node.kad_id.GetByteChunk(0);
			return node.kad_id.GetByteChunk(0) == id.GetByteChunk(0);
		}
	private:
		CUInt128 id;
	};
	class checkInSame8bitZoneAndAlive
	{
	public:
		checkInSame8bitZoneAndAlive(const CUInt128 & m_id):id(m_id){};

		bool operator()(const KadNode& node)
		{
			//return id.GetByteChunk(0)==comp_id.GetByteChunk(0);
			unsigned char byte = node.kad_id.GetByteChunk(0);
			return node.kad_id.GetByteChunk(0) == id.GetByteChunk(0) && node.verified==true;
		}
	private:
		CUInt128 id;
	};
    
}
