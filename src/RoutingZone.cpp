// RoutingZone.cpp: implementation of the RoutingZone class.
//
//////////////////////////////////////////////////////////////////////

#include "config.h"
#include "KadUtil.h"

using namespace KadCrawl;

RoutingZone::RoutingZone()
{
	m_pSuperZone = NULL;
	m_pSubZones[0]=NULL;
	m_pSubZones[1]=NULL;
	m_uLevel = 0;
	m_uZoneIndex = 0;
	m_pBin = new RoutingBin();
}

RoutingZone::RoutingZone(RoutingZone *pSuper_zone, int iLevel, CUInt128 &uZone_index)
{
	m_pSuperZone = pSuper_zone;
	m_uLevel = iLevel;
	m_uZoneIndex = uZone_index;

	m_pBin = new RoutingBin();
}

RoutingZone::~RoutingZone()
{
    if(m_pBin!=NULL)	
    {
        delete m_pBin;
        m_pBin = NULL;
    }
}

void RoutingZone::readKadNodesDataFile(string filepath)
{
	if(m_pSuperZone != NULL)
		return;
	ifstream fs;
	fs.open(filepath.c_str(),ios_base::binary|ios_base::in);

	if(fs.eof())
	{
		DEBUG_PRINT2("file open failed  %s\n",filepath.c_str());
		return;
	}

	unsigned long node_count=0;
	unsigned int version;
	fs.read((char*)&node_count,sizeof(node_count));
	if(node_count==0)
	{
		fs.read((char*)&version,sizeof(version));
		fs.read((char*)&node_count,sizeof(node_count));
	}
	
	DEBUG_PRINT2("nodes size: %lu\n",node_count);
	DEBUG_PRINT2("version:  %u\n",version);

	for(uint32 i=0;i<node_count;i++)
	{
		if(version >= 0 && version < 3)
		{
			if(version == 0)
			{
				
			}
			else
			{
				// Reading 34 bytes in total
				unsigned long kad_id[4]={0};
				unsigned char ip_array[4]={0};
				unsigned short udp_port=0;
				unsigned short tcp_port=0;
				unsigned char type=0;
				unsigned long kadUDPKey = 0;
				unsigned long kadUDPKeyIP=0;
				bool verified=false;
								
				fs.read((char*)kad_id,sizeof(unsigned long)*4);
				fs.read((char*)ip_array,sizeof(unsigned char)*4);
				fs.read((char*)&udp_port,sizeof(udp_port));
				fs.read((char*)&tcp_port,sizeof(tcp_port));
				fs.read((char*)&type,sizeof(type));
				fs.read((char*)&kadUDPKey,sizeof(unsigned long));
				fs.read((char*)&kadUDPKeyIP,sizeof(unsigned long));
				fs.read((char*)&verified,sizeof(verified));
				
				KadNode node;
				
				std::ostringstream stream;
				stream<<ip_array[3]<<"."<<ip_array[2]<<"."<<ip_array[1]<<"."<<ip_array[0];

				node.ipNetOrder = inet_addr(stream.str().c_str());
				node.udp_port = udp_port;
				node.tcp_port = tcp_port;
				node.version = type;
				node.kad_id.SetValueBE((BYTE*)kad_id);

				KadUDPKey key(kadUDPKey,kadUDPKeyIP);
				node.kadUDPkey = key;
								
				node.verified = verified;
			}
		}
	}
	
	fs.close();
	return;
}

bool RoutingZone::IsLeaf()
{
	return m_pBin != NULL;
}

bool RoutingZone::Add(KadNode *node)
{
	if(!IsLeaf())
		return m_pSubZones[node->GetDistance().GetBitNumber(m_uLevel)]->Add(node);
	else
	{
		KadNode* exist_node = m_pBin->GetContact(node->kad_id);
		if(exist_node)
		{
			exist_node->udp_port = node->udp_port;
			exist_node->tcp_port = node->tcp_port;
			exist_node->version = node->version;
			exist_node->kadUDPkey = node->kadUDPkey;
			if(!exist_node->verified)
			{
				exist_node->verified = node->verified;
			}
			//DEBUG_PRINT2("updating kad node info %s\n",exist_node->ipString.c_str());
			return true;
		}
		else if(m_pBin->GetRemaining())
		{
			if(m_pBin->AddNode(*node))
			{
				//DEBUG_PRINT4("node added %s  UDP:%d  TCP:%d\n",node->ipString.c_str(),node->udp_port,node->tcp_port);
				return true;
			}
			return false;
		}
		else if(CanSplit())
		{
			Split();
			return m_pSubZones[node->GetDistance().GetBitNumber(m_uLevel)]->Add(node);
		}
		else
			return false;
		
	}

}

bool RoutingZone::AddUnfiltered(const CUInt128 &uID,uint32 uIP,uint16 uUDPPort,uint16 uTCPPort,uint8 uVersion,KadUDPKey udpkey,bool& bIPVerified)
{
	if(uID != uMe)
	{
		KadNode* node = new KadNode(uID,uIP,uUDPPort,uTCPPort,KadUtil::kad_id,uVersion,udpkey,bIPVerified);
		boost::mutex::scoped_lock lock(nodeAddLock);
		bool ret = Add(node);
		delete node;
		return ret;
	}
	return false;
}

bool RoutingZone::CanSplit()
{
	if(m_uLevel >= 127)
		return false;
	if((m_uZoneIndex < KK || m_uLevel < KBASE) && m_pBin->GetSize() == K)
		return true;
	return false;
}

RoutingZone* RoutingZone::GenSubZone(int iSide)
{
	CUInt128 uNewIndex(m_uZoneIndex);
	uNewIndex.ShiftLeft(1);
	if(iSide != 0)
		uNewIndex.Add(1);
	return new RoutingZone(this,m_uLevel+1,uNewIndex);
}

void RoutingZone::Split()
{
	m_pSubZones[0] = GenSubZone(0);
	m_pSubZones[1] = GenSubZone(1);

	list<KadNode>::iterator it = m_pBin->nodeList.begin();
	while(it != m_pBin->nodeList.end())
	{
		KadNode node = *it;
		int iSuperZone = node.GetDistance().GetBitNumber(m_uLevel);
		m_pSubZones[iSuperZone]->m_pBin->AddNode(node);
		it++;
	}

	delete m_pBin;
	m_pBin = NULL;
}

string RoutingZone::dumpInfo(string prefix)
{
	std::ostringstream stream;

	if(IsLeaf())
	{
		stream<<"Prefix "<<prefix<<"  -------------------------"<<endl;
		m_pBin->setPrefixByLevel(m_uLevel);
		stream<<m_pBin->dumpInfo();
	}
	else
	{
		stream<<m_pSubZones[0]->dumpInfo(prefix.append("0"));
		stream<<endl<<"-------------------------"<<endl;
		stream<<m_pSubZones[1]->dumpInfo(prefix.append("1"));
	}

	return stream.str();
}

void RoutingZone::EnumerateNodes(int iDepth, ContactList &nodeList, bool bEmptyFirst)
{
	if(IsLeaf())
		m_pBin->GetEntries(nodeList,bEmptyFirst);
	else if(iDepth <= 0)
		RandomBin(nodeList,bEmptyFirst);
	else
	{
		m_pSubZones[0]->EnumerateNodes(iDepth-1,nodeList,bEmptyFirst);
		m_pSubZones[1]->EnumerateNodes(iDepth-1,nodeList,false);
	}
}

void RoutingZone::RandomBin(ContactList &nodeList, bool bEmptyFirst)
{
	if(IsLeaf())
		m_pBin->GetEntries(nodeList,bEmptyFirst);
	else
		m_pSubZones[rand()&1]->RandomBin(nodeList,bEmptyFirst);
}

void RoutingZone::EnumerateAllNodes(ContactList &nodeList)
{
	if(IsLeaf())
	{
		m_pBin->GetEntries(nodeList,false);
	}
	else
	{
		m_pSubZones[0]->EnumerateAllNodes(nodeList);
		m_pSubZones[1]->EnumerateAllNodes(nodeList);
	}
}
