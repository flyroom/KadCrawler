// RoutingBin.cpp: implementation of the RoutingBin class.
//
//////////////////////////////////////////////////////////////////////

#include "config.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

RoutingBin::RoutingBin()
{
	prefix="";
}

RoutingBin::~RoutingBin()
{
	
}


KadNode* RoutingBin::GetContact(const CUInt128 &uID)
{
	/*
	list<KadNode>::iterator it = nodeList.begin();
	while(it != nodeList.end())
	{
		KadNode& node = *it;
		if(node.kad_id == uID)
			return &node;
		it++;
	}
	*/
	
	KadNode node;
	node.kad_id = uID;
	ContactList::iterator it = lower_bound(nodeList.begin(),nodeList.end(),node);
	if(*it == node)
		return &(*it);
		
	return NULL;
}

UINT RoutingBin::GetRemaining()
{
	return (UINT)K - (UINT)nodeList.size();
	return 1;
}

bool RoutingBin::AddNode(KadNode target_node)
{
	/*
	list<KadNode>::iterator it = nodeList.begin();
	while(it != nodeList.end())
	{
		KadNode& node = *it;
		if(node.kad_id == target_node.kad_id)
			return false;
		it++;
	}
	*/
	
	if(binary_search(nodeList.begin(),nodeList.end(),target_node))
		return false;

	if(nodeList.size() < K)
	{
		//nodeList.push_back(target_node);
		nodeList.insert(find_if(nodeList.begin(),nodeList.end(),bind2nd(less<KadNode>(),target_node)),target_node);
	}
	
	/*
	ContactList::iterator it = lower_bound(nodeList.begin(),nodeList.end(),target_node);
	if(*it == target_node)
		return false;
	
	if(nodeList.size() < K)
		nodeList.insert(it,target_node);
		*/
	return true;
}

UINT RoutingBin::GetSize() const
{
	return (UINT)nodeList.size();
}

string RoutingBin::dumpInfo()
{
	std::ostringstream stream;

	list<KadNode>::iterator it = nodeList.begin();
	while(it != nodeList.end())
	{
		KadNode& node = *it;
		string line = prefix;
		line.append(node.dumpInfo());
		stream<<line<<endl;
		it++;
	}
	
	return stream.str();
}

void RoutingBin::setPrefixByLevel(UINT level)
{
	for(uint32 i=0;i<level;i++)
	{
		prefix.append(" ");
	}
}

void RoutingBin::GetEntries(ContactList &outList, bool bEmptyFirst)
{
	if(bEmptyFirst)
		outList.clear();
	if(nodeList.size() > 0)
	{
		outList.insert(outList.end(),nodeList.begin(),nodeList.end());
	}
}
