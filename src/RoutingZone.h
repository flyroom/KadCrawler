// RoutingZone.h: interface for the RoutingZone class.
//
//////////////////////////////////////////////////////////////////////

class RoutingZone  
{
public:
	void EnumerateAllNodes(ContactList& nodeList);
	void RandomBin(ContactList& nodeList,bool bEmptyFirst);
	void EnumerateNodes(int iDepth,ContactList &list,bool bEmptyFirst=true);
	bool CanSplit();
	bool Add(KadNode* node);
	bool AddUnfiltered(const CUInt128 &uID,uint32 uIP,uint16 uUDPPort,uint16 uTCPPort,uint8 uVersion,KadUDPKey udpkey,bool& bIPVerified);

	bool IsLeaf();
	RoutingZone(RoutingZone *pSuper_zone,int iLevel,CUInt128 &uZone_index);
	void readKadNodesDataFile(string filepath);
	RoutingZone* GenSubZone(int iSide);
	void Split();
	string dumpInfo(string prefix);
	RoutingZone();
	virtual ~RoutingZone();

	RoutingZone* m_pSubZones[2];
	RoutingZone* m_pSuperZone;

	CUInt128 uMe;

	UINT m_uLevel;
	CUInt128 m_uZoneIndex;

	boost::mutex nodeAddLock;
	
	RoutingBin *m_pBin;
};


