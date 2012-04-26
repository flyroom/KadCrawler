#include "config.h"
#include"KadUtil.h"

bool compareKadSharedFile(KadFileSource sourceA,KadFileSource sourceB)
{
	if(sourceA.sourceIP != sourceB.sourceIP)
		return htonl(sourceA.sourceIP)<htonl(sourceB.sourceIP);
	else if( sourceA.serverTcpPort != sourceB.serverTcpPort)
		return sourceA.serverTcpPort < sourceB.serverTcpPort;
	else if(sourceA.uType != sourceB.uType)
		return sourceA.uType < sourceB.uType;
	else
		return false;
}

bool equalKadSharedFile(KadFileSource sourceA,KadFileSource sourceB)
{
	return sourceA.sourceIP==sourceB.sourceIP&&sourceA.serverTcpPort==sourceB.serverTcpPort&&sourceA.uType==sourceB.uType;
}

KadSharedFile::KadSharedFile(void)
{
}

KadSharedFile::~KadSharedFile(void)
{
}

bool KadSharedFile::addKadFileSource(KadFileSource& source)
{
	sourceList.push_back(source);
	return true;
}

bool KadSharedFile::addKadKeywordNode(KadKeywordNode& keywordNode)
{
	keywordNodeList.push_back(keywordNode);
	return true;
}

void KadSharedFile::removeDuplicates()
{
	sort(sourceList.begin(),sourceList.end(),compareKadSharedFile);
	sourceList.erase(unique(sourceList.begin(),sourceList.end(),equalKadSharedFile),sourceList.end());

	sort(keywordNodeList.begin(),keywordNodeList.end());
	keywordNodeList.erase(unique(keywordNodeList.begin(),keywordNodeList.end()),keywordNodeList.end());
}

string KadSharedFile::dumpInfo()
{
	std::ostringstream stream;
	stream<<"--------------------"<<endl;;
	stream<<"fileHash: "<<fileHash.ToHexString()<<" ";
	stream<<"fileLength: "<<fileSize<<" ";
	stream<<"keyword id: "<<keywordID.ToHexString()<<endl;
	stream<<"keyword Nodes :"<<keywordNodeList.size()<<endl;
	for(unsigned int j=0;j<keywordNodeList.size();j++)
	{
		stream<<"		"<<inet_ntoa(*((in_addr*)&keywordNodeList[j].srcNodeIP))<<" : "<<keywordNodeList[j].srcNodeUdpPort<<"  "<<keywordNodeList[j].fileName<<"  "<<keywordNodeList[j].srcNodeID.ToHexString()<<endl;
	}
	stream<<"Source Nodes :"<<sourceList.size()<<endl;
    unsigned long static_count=0;
    unsigned long firewalled_count=0;
    unsigned long firewalled_callback_count=0;
	for(unsigned int i=0;i<sourceList.size();i++)
	{
		stream<<"		"<<inet_ntoa(*((in_addr*)&sourceList[i].sourceIP))<<" : "<<sourceList[i].serverTcpPort<<" ";
		switch(sourceList[i].uType)
		{
		case 4:
		case 1:
			stream<<"static address ";
            static_count++;
			break;
		case 5:
		case 3:
			stream<<"firewalled ";
            firewalled_count++;
			break;
		case 6:
			stream<<"firewalled with callback ";
            firewalled_callback_count++;
			break;
		}

		using namespace KadCrawl;
		stream<<KadUtil::getCountryNameFromIP(sourceList[i].sourceIP);
		stream<<endl;
	}
    if(sourceList.size()==0)
    {
        stream<<"no sources found for this file"<<endl;
    }
    else
    {
        stream<<"static nodes size: "<<static_count<<"  "<<((double)(static_count/sourceList.size())*100)<<"%"<<endl;
        stream<<"firewalled_count: "<<firewalled_count<<"  "<<((double)(firewalled_count/sourceList.size())*100)<<"%"<<endl;
        stream<<"firewalled_callback_count: "<<firewalled_callback_count<<"  "<<((double)(firewalled_callback_count/sourceList.size())*100)<<"%"<<endl;
	    stream<<"--------------------"<<endl;
    }
   	return stream.str();
}

