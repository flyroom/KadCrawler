// KadNode.cpp: implementation of the KadNode class.
//
//////////////////////////////////////////////////////////////////////

#include"config.h"
#include"KadUtil.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

void KadUDPKey::fromInt64String(char *str)
{
#ifdef WIN32
	__int64 key_num;
	key_num = _atoi64(str);
#else
	long long key_num;
	key_num = atoll(str);
#endif
	m_dwKey = key_num >> 32;
	m_dwIP = key_num&(-1);
}

KadNode::KadNode()
{
	version = -1;
	udp_port = 0;
	tcp_port = 0;
	verified = false;
	ipNetOrder = 0;
	parentIpAddr = 0;
    count = 0;
    state = KAD_DEAD;
}
KadNode::~KadNode()
{}
string KadNode::dumpInfo()
{
	std::ostringstream stream,id_stream,type_stream;
	type_stream << (unsigned int)version;
	id_stream << kad_id.ToHexString();
	struct in_addr addr;
	memcpy(&addr,&ipNetOrder,sizeof(uint32));
	stream<<inet_ntoa(addr)<<" "<<tcp_port<<" "<<udp_port<<" "<<type_stream.str()<<" "<<id_stream.str()<<" "<<verified<<"   ";
    stream<<KadCrawl::KadUtil::getFullIpGeoInfoFromIP(ipNetOrder)<<endl;
    if(parentIpAddr != 0)
    {
        stream<<"        ";
        stream<<inet_ntoa(*((in_addr*)&parentIpAddr));
        stream<<KadCrawl::KadUtil::getFullIpGeoInfoFromIP(parentIpAddr);
    }
	return stream.str();
}
KadNode::KadNode(const CUInt128 &uClientID, uint32 uIp, uint16 uUdpPort, uint16 uTcpPort, const CUInt128 &uTarget, uint8 uVersion, KadUDPKey udpKey, bool ipVerified)
{
	this->kad_id = uClientID;
	this->ipNetOrder = uIp;
	this->udp_port = uUdpPort;
	this->tcp_port = uTcpPort;
	this->version = uVersion;
	this->kadUDPkey = udpKey;
	this->verified = ipVerified;
	this->parentIpAddr = 0;
    this->count = 0;
    state = KAD_DEAD;
//	this->m_uDistance.SetValue(uTarget);
//	this->m_uDistance.Xor(uClientID);
}
KadNode::KadNode(const CUInt128 &uClientID, uint32 uIp, uint16 uUdpPort, uint16 uTcpPort, const CUInt128 &uTarget, uint8 uVersion, KadUDPKey udpKey, bool ipVerified,unsigned long ipaddr)
{
	this->kad_id = uClientID;
	this->ipNetOrder = uIp;
	this->udp_port = uUdpPort;
	this->tcp_port = uTcpPort;
	this->version = uVersion;
	this->kadUDPkey = udpKey;
	this->verified = ipVerified;
	this->parentIpAddr = ipaddr;
    this->count = 0;
    state = KAD_DEAD;
//	this->m_uDistance.SetValue(uTarget);
//	this->m_uDistance.Xor(uClientID);
}
CUInt128 KadNode::GetDistance()
{
	//return m_uDistance;
    return CUInt128((unsigned long)0);
}
