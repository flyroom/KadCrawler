#include "config.h"
#include "KadUtil.h"
#include "KadClientCredits.h"
#include "FileClientSession.h"
#include "KadFileDownloader.h"
#include "KadScanner.h"

using namespace KadCrawl;

extern KadScanner scanner;
extern KadClientCreditsPool creditsPool;

extern CryptoPP::AutoSeededRandomPool cryptRandomGen;

KadFileDownloader::KadFileDownloader(void)
{
}

KadFileDownloader::~KadFileDownloader(void)
{
}

void KadFileDownloader::Init()
{
	uchar achKeyData[21];
	uint32 m_nRandomKeyPart = cryptRandomGen.GenerateWord32();
	md4cpy(achKeyData,&KadUtil::client_hash);
	memcpy(achKeyData+17,&m_nRandomKeyPart,4);

	uchar md5sum[16]={0};
	MD5 md5;
	md5.Update(achKeyData,sizeof(achKeyData));
	md5.Final(md5sum);

	achKeyData[16] = MAGICVALUE_REQUESTER;
	m_pRC4SendKey= RC4CreateKey(md5sum,16,NULL);
	achKeyData[16] = MAGICVALUE_SERVER;
	md5.Update(achKeyData,sizeof(achKeyData));
	md5.Final(md5sum);
	m_pRC4ReceiveKey = RC4CreateKey(md5sum,16,NULL);

	creditsPool.InitalizeCrypting();
}

void KadFileDownloader::sendPacket(unsigned long ipaddr,boost::shared_ptr<Packet> pPacket)
{
	unsigned char* buffer = pPacket->DetachPacket();
	unsigned buf_len = pPacket->size+6;
	scanner.getTcpEngine()->send_sync(ipaddr,buffer,buf_len);
}

boost::shared_ptr<Packet> KadFileDownloader::receivePacket(string ip)
{
	unsigned long len=0;
	unsigned char* buffer = scanner.getTcpEngine()->receive_sync(ip,&len);

	if(len == 0)
		return boost::shared_ptr<Packet>((Packet*)NULL);

	boost::shared_ptr<Packet> receivedPacket(new Packet((char*)buffer));

	receivedPacket->pBuffer = new char[receivedPacket->size+1];
	memcpy(receivedPacket->pBuffer,buffer+6,receivedPacket->size);
	
	return receivedPacket;
}

void KadFileDownloader::CryptPrepareSendData(unsigned char* pBuffer,uint32 nLen)
{
	RC4Crypt(pBuffer,pBuffer,nLen,m_pRC4SendKey);
}

Packet* KadFileDownloader::BuildHelloPacket()
{
	SafeMemFile dataIO;
	dataIO.WriteUInt8(16);
	dataIO.WriteUInt128(&KadUtil::client_hash);
	dataIO.WriteUInt32(1);
	dataIO.WriteUInt16(KadCrawl::KadUtil::udp_port);

	uint32 tagcount=6;

	bool bSendModVersion = 1;
	if(bSendModVersion)
		tagcount++;

	// this fake node is of course firewalled,tagcount need to add 1
	dataIO.WriteUInt32(tagcount);

	// send the standard nick pretend to be a normal client as the emule0.50 recommend
	YTag tagName(CT_NAME,"red army");
	tagName.WriteTagToFile(&dataIO);

	YTag tagVersion(CT_VERSION,EDONKEYVERSION);
	tagVersion.WriteTagToFile(&dataIO);

	YTag tagUdpPorts(CT_EMULE_UDPPORTS,((uint32)KadCrawl::KadUtil::udp_port<<16) |
		((uint32)KadCrawl::KadUtil::udp_port<<0)
		);
	tagUdpPorts.WriteTagToFile(&dataIO);

	// eMule Misc Option 1
	const UINT uUdpVer	= 4;
	const UINT uDataCompVer = 1;
	// cryptoAvailable
	const UINT uSupportSecIdent = 3;
	const UINT uSourceExchange1Ver = 4;
	const UINT uExtendRequestsVer= 2;
	const UINT uAcceptCommentVer = 1;
	const UINT uNoViewSharedFiles = 1;
	const UINT uMultiPacket = 1;
	const UINT uSupportPreview = 0;
	const UINT uPeerCache	= 1;
	const UINT uUnicodeSupport = 1;
	const UINT nAICHVer = 1;

	YTag tagMisOptions1(CT_EMULE_MISCOPTION1,
		(nAICHVer << 29) |
		(uUnicodeSupport << 28) |
		(uUdpVer << 24) |
		(uDataCompVer << 20) |
		(uSupportSecIdent << 16) |
		(uExtendRequestsVer << 8) |
		(uAcceptCommentVer << 4) |
		(uNoViewSharedFiles << 2) |
		(uMultiPacket << 1) |
		(uSupportPreview << 0)
		);
	tagMisOptions1.WriteTagToFile(&dataIO);

	// eMule Misc Option 2
	const UINT uKadVersion = KADEMLIA_VERSION9_50a;
	const UINT uSupportLargeFiles = 1;
	const UINT uExtMultiPacket = 1;
	const UINT uReserved = 0;
	const UINT uSupportsCryptLayer = 1;
	const UINT uRequestsCryptLayer = 0;
	const UINT uRequiresCryptLayer = 0;
	const UINT uSupportsSourceEx2 = 1;
	const UINT uSupportsCaptcha = 1;

	const UINT uDirectUDPCallback = 0;
	const UINT uFileIdentifiers = 1;

	YTag tagMisOption2(CT_EMULE_MISCOPTION2,
		(uFileIdentifiers << 13) |
		(uDirectUDPCallback << 12) |
		(uSupportsCaptcha << 11) |
		(uRequiresCryptLayer << 9) |
		(uRequiresCryptLayer << 8) |
		(uRequiresCryptLayer << 7) |
		(uReserved << 6) |
		(uExtMultiPacket << 5) |
		(uSupportLargeFiles << 4) |
		(uKadVersion << 0)
		);
	tagMisOption2.WriteTagToFile(&dataIO);

	const UINT m_nVersionMjr = 0;
	const UINT m_nVersionMin = 50;
	const UINT m_nVersionUpd = 0;
	YTag tagMuleVersion(CT_EMULE_VERSION,
		m_nVersionMjr << 17 |
		m_nVersionMin << 10 |
		m_nVersionUpd << 7
		);

	tagMuleVersion.WriteTagToFile(&dataIO);

	if(bSendModVersion)
	{
		YTag tagMODVersion(ET_MOD_VERSION,MOD_VERSION);
		tagMODVersion.WriteTagToFile(&dataIO);
	}

	uint32 ed2k_serverIP=0;
	uint16 ed2k_port=0;
	dataIO.WriteUInt32(ed2k_serverIP);
	dataIO.WriteUInt16(ed2k_port);

	Packet* packet = new Packet((char*)dataIO.memBuffer,dataIO.file_size);
	packet->opcode = OP_HELLO;
	return packet;
}

bool KadFileDownloader::Connect(KadNode& node)
{
	string ip = inet_ntoa(*((in_addr*)&node.ipNetOrder));
	bool connected = scanner.getTcpEngine()->connect(ip,node.tcp_port);
	if(!connected)
	{
		DEBUG_PRINT2("connect failed to %s",ip.c_str());
		return false;
	}

	boost::shared_ptr<Packet> packet(BuildHelloPacket());
	sendPacket(node.ipNetOrder,packet);
	
	//receive the OP_HELLOANSWER
	ProcessPacket(node.ipNetOrder,receivePacket(ip));
	//receive the OP_SECIDENTSTATE and send OP_PUBLICKEY,OP_SIGNATURE
	ProcessPacket(node.ipNetOrder,receivePacket(ip));
	// receive OP_PUBLICKEY
	ProcessPacket(node.ipNetOrder,receivePacket(ip));

	scanner.getTcpEngine()->disconnect(ip);
	return true;
}

void KadFileDownloader::ProcessPacket(unsigned long ip,const boost::shared_ptr<Packet> p)
{
	if(p == NULL)
	{
		DEBUG_PRINT1("received invalid packet\n");
		return;
	}
	userIpMap_it it = userIpSessions.find(ip);

	boost::shared_ptr<FileClientSession> pSession;
	if(it == userIpSessions.end())
	{
		boost::shared_ptr<FileClientSession> pTempSession(new FileClientSession());
		userIpSessions[ip] = pTempSession;
		pSession = pTempSession;
		pSession->ipaddr = ip;
	}
	else
	{
		pSession = it->second;
	}

	switch(p->prot)
	{
	case OP_EDONKEYPROT:
		ProcessEDonkeyPacket(pSession,p);
		break;
	case OP_PACKEDPROT:
	case OP_EMULEPROT:
		ProcessEmulePacket(pSession,p);
		break;
	default:
		DEBUG_PRINT1("received wrong header \n");
		return;
	}

	switch(p->opcode)
	{
		case OP_SENDINGPART:
		case OP_COMPRESSEDPART:
		case OP_COMPRESSEDPART_I64:
			{
				
			}
	}
}

void KadFileDownloader::ProcessEDonkeyPacket(boost::shared_ptr<FileClientSession> pIpSession,const boost::shared_ptr<Packet> p)
{
	switch(p->opcode)
	{
	case OP_HELLOANSWER:
		DEBUG_PRINT1("received OP_HELLOANSWER message\n");
		ProcessHelloAnswer(pIpSession,p);
		break;
	case OP_HELLO:
		DEBUG_PRINT1("received OP_HELLO message\n");
		break;
	case OP_SECIDENTSTATE:
		DEBUG_PRINT1("received OP_SECIDENTSTATE message\n");
		break;
	case OP_ASKSHAREDFILESANSWER:
		DEBUG_PRINT1("received OP_ASKSHAREDFILESANSWER message\n");
		break;
	case OP_ASKSHAREDFILESDIRANS:
		DEBUG_PRINT1("received OP_ASKSHAREDFILESDIRANS message\n");
		break;
	}
}

void KadFileDownloader::ProcessEmulePacket(boost::shared_ptr<FileClientSession> pIpSession,const boost::shared_ptr<Packet> packet)
{
	switch(packet->opcode)
	{
	case OP_SECIDENTSTATE:
		ProcessSecIdentStatePacket(pIpSession,packet);
		break;
	case OP_PUBLICKEY:
		ProcessPublicKeyPacket(pIpSession,packet);
		break;
	case OP_SIGNATURE:
		ProcessSignaturePacket(pIpSession,packet);
		break;
	}
}

void KadFileDownloader::ProcessHelloAnswer(boost::shared_ptr<FileClientSession> pIpSession,const boost::shared_ptr<Packet> p)
{
	SafeMemFile data((uchar*)p->pBuffer,p->size);
	data.ReadByteArray((char*)&pIpSession->user_hash,16);
	
	pIpSession->processHelloAnswer(data);

	boost::shared_ptr<Packet> packet = pIpSession->createSecIdentStatePacket();
	if(packet != NULL)
		sendPacket(pIpSession->ipaddr,packet);
}

void KadFileDownloader::ProcessSecIdentStatePacket(boost::shared_ptr<FileClientSession> pIpSession,const boost::shared_ptr<Packet> p)
{
	SafeMemFile data((uchar*)p->pBuffer,p->size);
	pIpSession->ProcessSecIdentStatePacket(data);
	if(pIpSession->secureState == IS_SIGNATURENEEDED)
	{	
		boost::shared_ptr<Packet> pPacket = pIpSession->createSignaturePacket();
		if(pPacket != NULL)
			sendPacket(pIpSession->ipaddr,pPacket);
		else
		{
			DEBUG_PRINT1("Creating signature packet failed\n");	
		}
	}
	else if(pIpSession->secureState == IS_KEYANDSIGNEEDED)
	{
		boost::shared_ptr<Packet> pubkey_packet = pIpSession->createPublicKeyPacket();
		if(pubkey_packet != NULL)
		{
			sendPacket(pIpSession->ipaddr,pubkey_packet);
			boost::shared_ptr<Packet> sig_packet = pIpSession->createSignaturePacket();
			if(sig_packet != NULL)
				sendPacket(pIpSession->ipaddr,sig_packet);
			else
			{
				DEBUG_PRINT1("Creating signature packet failed\n");	
			}
		}
		else
		{
			DEBUG_PRINT1("Creating publickey packet failed\n");	
		}
	}
}

void KadFileDownloader::ProcessPublicKeyPacket(boost::shared_ptr<FileClientSession> pIpSession,const boost::shared_ptr<Packet> packet)
{
	if(pIpSession->client_credit.SetSecureIdent((unsigned char*)(packet->pBuffer+1),packet->pBuffer[0]))
	{
		if(pIpSession->secureState == IS_SIGNATURENEEDED)
		{
			boost::shared_ptr<Packet> sig_packet = pIpSession->createSignaturePacket();
			if(sig_packet != NULL)
				sendPacket(pIpSession->ipaddr,sig_packet);
			else
			{
				DEBUG_PRINT1("Creating signature packet failed\n");	
			}
		}
		else if(pIpSession->secureState == IS_KEYANDSIGNEEDED)
		{
			DEBUG_PRINT1("Invalid state error IS_KEYANDSIGNEEDED in ProcessPublicKeyPacket\n");
		}
	}
	else
	{
		DEBUG_PRINT1("Failed to use new received public key\n");
	}
}

void KadFileDownloader::ProcessSignaturePacket(boost::shared_ptr<FileClientSession> pIpSession,const boost::shared_ptr<Packet> p)
{
	unsigned char* pBuffer = (unsigned char*)p->pBuffer;
	unsigned long len = p->size;
	uint8 chaIPKind;
	if(pBuffer[0] == len-1)
		chaIPKind = 0;
	else if(pBuffer[0] == len-2 && ((pIpSession->by_supportSecIdent&2)>0))
		chaIPKind = pBuffer[len-1];
	else
		return;
	if(pIpSession->client_credit.GetSecIDKeyLen()==0)
		return;
	if(pIpSession->client_credit.cryptRndChallengeFor == 0)
		return;

	if(creditsPool.VerifyIdent(&pIpSession->client_credit,pBuffer+1,pBuffer[0],pIpSession->ipaddr,chaIPKind))
	{
		DEBUG_PRINT2("节点 %s 通过认证\n",inet_ntoa(*((in_addr*)&pIpSession->ipaddr)));
		return;
	}
}
