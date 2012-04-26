#pragma once

#define MAGICVALUE_REQUESTER			34
#define MAGICVALUE_SERVER				203
#define MAGICVALUE_SYNC					0x835E6FC4

typedef map<userkey_hash,boost::shared_ptr<FileClientSession> > userHashMap;
typedef userHashMap::iterator userHashMap_it;

typedef map<unsigned long,boost::shared_ptr<FileClientSession> > userIpMap;
typedef userIpMap::iterator userIpMap_it;

class KadFileDownloader
{
public:
	KadFileDownloader(void);
	~KadFileDownloader(void);

	void Init();
	bool Connect(KadNode& node);
private:
	void sendPacket(unsigned long ipaddr,boost::shared_ptr<Packet> pPacket);
	boost::shared_ptr<Packet> receivePacket(string ip);

	void ProcessPacket(unsigned long ip,const boost::shared_ptr<Packet> p);
	void ProcessEmulePacket(boost::shared_ptr<FileClientSession>,const boost::shared_ptr<Packet> p);
	void ProcessEDonkeyPacket(boost::shared_ptr<FileClientSession>,const boost::shared_ptr<Packet> p);
	void ProcessHelloAnswer(boost::shared_ptr<FileClientSession>,const boost::shared_ptr<Packet> p);
	void ProcessSecIdentStatePacket(boost::shared_ptr<FileClientSession> pIpSession,const boost::shared_ptr<Packet> p);
	void ProcessPublicKeyPacket(boost::shared_ptr<FileClientSession> pIpSession,const boost::shared_ptr<Packet> p);
	void ProcessSignaturePacket(boost::shared_ptr<FileClientSession> pIpSession,const boost::shared_ptr<Packet> p);

	void CryptPrepareSendData(unsigned char* pBuffer,uint32 nLen);

private:
	Packet* BuildHelloPacket();

	RC4_Key_Struct* m_pRC4SendKey;
	RC4_Key_Struct* m_pRC4ReceiveKey;

	KadFileDownloader* filedownloader;
		
	userHashMap userSessions;
	userIpMap userIpSessions;

	KadClientCredits clientcredits;
};
