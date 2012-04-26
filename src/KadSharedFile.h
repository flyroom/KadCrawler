#pragma once
typedef struct _KadKeywordNode
{
	string fileName;
	// the node who sent the keyword search answer packet
	CUInt128 srcNodeID;
	uint32 srcNodeIP;
	uint16 srcNodeUdpPort;

	string media_artist;
	string media_album;
	string media_title;
	uint32 media_length;
	uint32 media_bitrate;
	string media_codec;

	bool operator < (const _KadKeywordNode &uValue) const
	{
		if(srcNodeUdpPort != uValue.srcNodeUdpPort)
			return srcNodeUdpPort < uValue.srcNodeUdpPort;
		else if(srcNodeID != uValue.srcNodeID)
			return srcNodeID < uValue.srcNodeID;
		else if(srcNodeIP != uValue.srcNodeIP)
			return srcNodeIP < uValue.srcNodeIP;
		return false;
	}

	bool operator == (const _KadKeywordNode& file) const
	{
		return srcNodeID == file.srcNodeID 
			&& srcNodeIP == file.srcNodeIP 
			&& srcNodeUdpPort == file.srcNodeUdpPort;
	}

}KadKeywordNode;

typedef struct _KadFileSource
{
	uint32 sourceIP;

	uint16 serverTcpPort;
	uint16 serverUdpPort;
	//Buddy
	CUInt128 buddyID;
	uint32 buddyIP;
	uint16 buddyPort;
	// node type
	/*
	4,1: NonFirewalled users
	2: Wrong clients
	5,3: firewalled client connected to Kad only
	6: firewalled source which supports direct udp callback
	*/
	uint8 uType;

	bool operator == (const _KadFileSource& otherSource) const
	{
		return sourceIP == otherSource.sourceIP && serverTcpPort == otherSource.serverTcpPort && uType == otherSource.uType;
	}

	bool operator < (const _KadFileSource& otherSource) const
	{
		if(sourceIP != otherSource.sourceIP)
			return sourceIP<otherSource.sourceIP;
		else if( serverTcpPort != otherSource.serverTcpPort)
			return serverTcpPort < otherSource.serverTcpPort;
		else if(uType != otherSource.uType)
			return uType < otherSource.uType;
		else 
			return false;
	}

}KadFileSource;

class KadSharedFile
{
public:
	KadSharedFile(void);
	~KadSharedFile(void);

	unsigned long fileSize;
	unsigned long sourceCount;

	// keyword string id
	CUInt128 keywordID;
	CUInt128 fileHash;

	vector<KadFileSource> sourceList;
	vector<KadKeywordNode> keywordNodeList;

	bool addKadFileSource(KadFileSource& source);
	bool addKadKeywordNode(KadKeywordNode& keywordNode);
		
	string dumpInfo();

	void removeDuplicates();

	bool operator == (const KadSharedFile& file) const
	{
		return fileHash == file.fileHash && fileSize == file.fileSize;
	}
	bool operator < (const KadSharedFile &uValue) const
	{
		if(!(fileHash == uValue.fileHash))
			return fileHash < uValue.fileHash;
		else if(fileSize != uValue.fileSize)
			return fileSize < uValue.fileSize;
		else
			return false;
	}
};
