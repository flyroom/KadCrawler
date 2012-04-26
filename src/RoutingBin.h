// RoutingBin.h: interface for the RoutingBin class.
//
//////////////////////////////////////////////////////////////////////

typedef list<KadNode> ContactList;

class RoutingBin  
{
public:
	void GetEntries(ContactList &nodeList,bool bEmptyFirst);
	void setPrefixByLevel(UINT level);
	UINT GetSize() const;
	bool AddNode(KadNode node);
	UINT GetRemaining();
	KadNode* GetContact(const CUInt128 &uID);
	string dumpInfo();
	RoutingBin();
	virtual ~RoutingBin();
	
	list<KadNode> nodeList;
	string prefix;
};


