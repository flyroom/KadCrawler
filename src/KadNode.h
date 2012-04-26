#pragma once
typedef enum _NODE_STATE
{
    KAD_DEAD,
    KAD_ALIVE,
    KAD_UNMATCHED,
    KAD_NONE
}NODE_STATE;
class KadUDPKey
{
public:
	KadUDPKey(uint32 uZero = 0)											{assert(uZero == 0); m_dwKey = uZero; m_dwIP = 0;}
	KadUDPKey(uint32 dwKey, uint32 dwIP)									{m_dwKey = dwKey; m_dwIP = dwIP;}
	KadUDPKey& operator=(const KadUDPKey& k1)								{m_dwKey = k1.m_dwKey; m_dwIP = k1.m_dwIP; return *this; }
	KadUDPKey& operator=(const uint32 uZero)								{assert(uZero == 0); m_dwKey = uZero; m_dwIP = 0; return *this; }
	friend bool operator==(const KadUDPKey& k1,const KadUDPKey& k2)		{return k1.GetKeyValue(k1.m_dwIP) == k2.GetKeyValue(k2.m_dwIP);}
	
	uint32	GetKeyValue(uint32 dwMyIP)	const								{return (dwMyIP == m_dwIP) ? m_dwKey : 0;}
	bool	IsEmpty() const													{return (m_dwKey == 0) || (m_dwIP == 0);}
	uint64  GetInt64Value() const											
	{
		uint64 value = m_dwKey;
		value = (value<<32) + m_dwIP;
		return value;
	}

	void fromInt64String(char *str);
	
	uint32		m_dwKey;
	uint32		m_dwIP;
};
typedef struct _KadNodeStruct
{
	uint32 id[4];
	uint16 udp_port;
	uint32 ipNetOrder;
}KadNodeStruct;
class SimpleKadNode
{
protected:
	SimpleKadNode(){};
public:
	CUInt128 kad_id;
	uint16 udp_port;
	uint32 ipNetOrder;
	
	SimpleKadNode(CUInt128 id,uint32 port,uint32 ip):kad_id(id),udp_port(port),ipNetOrder(ip){};
	bool operator == (const SimpleKadNode& target) const
	{
		return kad_id == target.kad_id && ipNetOrder == target.ipNetOrder && udp_port == target.udp_port;
	}
	bool operator < (const SimpleKadNode &uValue) const
	{
		if(!(kad_id == uValue.kad_id))
			return kad_id < uValue.kad_id;
		else if(ipNetOrder != uValue.ipNetOrder)
			return ntohl(ipNetOrder) < ntohl(uValue.ipNetOrder);
		else if(udp_port != uValue.udp_port)
			return udp_port < uValue.udp_port;
		else
			return false;
	}
};
class SearchKadNode;
class KadNode:public SimpleKadNode
{
public:
	KadNode();
	virtual ~KadNode();

public:
	CUInt128 GetDistance();
	KadNode(const CUInt128 &uClientID,uint32 uIp,uint16 uUdpPort,uint16 uTcpPort,const CUInt128 &uTarget,uint8 uVersion,KadUDPKey udpKey,bool ipVerified);
	KadNode(const CUInt128 &uClientID, uint32 uIp, uint16 uUdpPort, uint16 uTcpPort, const CUInt128 &uTarget, uint8 uVersion, KadUDPKey udpKey, bool ipVerified,unsigned long ipaddr);
	string dumpInfo();

	KadNode& operator =(const KadNode &other)
	{
		kad_id = other.kad_id;
		version = other.version;
		udp_port = other.udp_port;
		tcp_port = other.tcp_port;
		kadUDPkey = other.kadUDPkey;
		verified = other.verified;
		ipNetOrder = other.ipNetOrder;
		return *this;
	}
    
	unsigned char version;
    unsigned char node_type;
	unsigned short tcp_port;
	KadUDPKey kadUDPkey;
	bool verified;
    NODE_STATE state;
	
    unsigned short count;
	unsigned long parentIpAddr;
//	CUInt128 m_uDistance;
};
class SearchKadNode:public KadNode
{
public:
    unsigned long full_ip;
};
class KadNodeEx:public KadNode
{ 
public:
    // how many times do each unique node present in some one's routing table in each round of crawling
    vector<unsigned short> history;
};
class SessionKadNode:public SimpleKadNode
{
public:
    vector<unsigned long> livePeriods;
};
