#include "config.h"
#include "KadClientCredits.h"
#include "FileClientSession.h"

extern KadClientCreditsPool creditsPool;

#define MAKE_CLIENT_VERSION(mjr,min,upd) \
		((UINT)(mjr)*100U*10U*100U+(UINT)(min)*100U*10U+(UINT)(upd)*100U)

FileClientSession::FileClientSession(void)
{
	ul_emuleTags = 0;
	user_name="";
	b_isHybrid = false;
	b_gplEvildoer=false;

	buddy_port=0;
	buddy_ip=0;
}

FileClientSession::~FileClientSession(void)
{
}

int FileClientSession::GetHashType()
{
	char* hash = (char*)user_hash.hash;
	if(hash[5]==13 && hash[14]==110)
		return SO_OLDEMULE;
	else if(hash[5] == 14 && hash[14] == 111)
		return SO_EMULE;
	else if(hash[5] =='M' && hash[14]=='L')
		return SO_MLDONKEY;
	else
		return SO_UNKNOWN;
}

void FileClientSession::InitClientSoftwareVersion()
{
	if(user_name=="")
	{
		client_softversion = SO_UNKNOWN;
	}

	int iHashType = GetHashType();
	if(iHashType == SO_EMULE)
	{
		switch(by_compatibleClient)
		{
		case SO_CDONKEY:
			str_software = "cDonkey";
			break;
		case SO_XMULE:
			str_software = "xMule";
			break;
		case SO_AMULE:
			str_software = "aMule";
			break;
		case SO_SHAREAZA:
		case 40:
			str_software = "lphant";
			break;
		case SO_LPHANT:
			break;
		default:
			str_software="unknown";
		}

		if(by_emuleVersion = 0)
		{
			u_clientVersion = MAKE_CLIENT_VERSION(0,0,0);
		}
		else if(by_emuleVersion != 0x99)
		{
			UINT nClientMinVersion = (by_emuleVersion>>4)*10+(by_emuleVersion&0x0f);
			u_clientVersion = MAKE_CLIENT_VERSION(0,nClientMinVersion,0);
		}
		else
		{
			UINT nClientMajVersion = (u_clientVersion>>17)&0x7f;
			UINT nClientMinVersion = (u_clientVersion>>10)&0x7f;
			UINT nClientUpVersion = (u_clientVersion>>7)&0x7f;
			u_clientVersion = MAKE_CLIENT_VERSION(nClientMajVersion,nClientMinVersion,nClientUpVersion);
		}
	}
}

void FileClientSession::processHelloAnswer(SafeMemFile& data)
{
	this->user_id_hybrid = data.ReadUInt32();
	this->user_port = data.ReadUInt16();

	uint32 tagcount = data.ReadUInt32();
	for(uint32 i=0;i<tagcount;i++)
	{
		YTag tag(data);
		switch(tag.GetNameID())
		{
		case CT_NAME:
			if(tag.IsStr())
			{
				this->user_name = tag.GetStr();
			}
			break;
		case CT_VERSION:
			if(tag.IsInt())
			{
				this->u_clientVersion = tag.GetInt();
			}
			break;
		case CT_PORT:
			if(tag.IsInt())
			{
				this->user_port_mod = (uint16)tag.GetInt();
			}
			break;
		case CT_MOD_VERSION:
			{
				if(tag.IsStr())
				{
					this->mod_version = tag.GetStr();
				}
				else if(tag.IsInt())
				{
					std::ostringstream stream;
					stream<<"ModID=";
					stream<<tag.GetInt();
					this->mod_version= stream.str();
				}
			}
			break;
		case CT_EMULE_UDPPORTS:
			{
				if(tag.IsInt())
				{
					this->kad_port = (uint16)(tag.GetInt()>>16);
					this->udp_port = (uint16)(tag.GetInt());
				}
			}
			break;
		case CT_EMULE_BUDDYUDP:
			{
				if(tag.IsInt())
				{
					this->buddy_port = tag.GetInt();
				}
			}
			break;
		case CT_EMULE_BUDDYIP:
			{
				if(tag.IsInt())
				{
					this->buddy_ip = tag.GetInt();
				}
			}
			break;
		case CT_EMULE_MISCOPTION1:
			{
				if(tag.IsInt())
				{

					this->bit_supportsAICH = (tag.GetInt()>>29)&0x07;
					this->b_unicodeSupport =(tag.GetInt()>>28)&0x01;
					this->by_udpVersion = (uint8)((tag.GetInt()>>24)&0x0f);
					this->by_dataCompVer = (uint8)((tag.GetInt()>>20)&0x0f);
					this->by_supportSecIdent = (uint8)((tag.GetInt()>>16)&0x0f);
					this->by_sourceExchange1Ver = (uint8)((tag.GetInt()>>12)&0x0f);
					this->by_extendedRequestsVer = (uint8)((tag.GetInt()>>8)&0x0f);
					this->by_acceptCommentVer = (uint8)((tag.GetInt()>>4)&0x0f);
					this->bit_peerCache = (tag.GetInt()>>3)&0x01;
					this->bit_noViewSharedFiles = (tag.GetInt()>>3)&0x01;
					this->b_multiPacket = (tag.GetInt()>>3)&0x01;
					this->bit_supportsPreview = (tag.GetInt()>>3)&0x01;
					this->ul_emuleTags |= 2;

				}
			}
		case CT_EMULE_MISCOPTION2:
			{
				if(tag.IsInt())
				{
					this->bit_supportsFileIdent = (tag.GetInt()>>13)&0x01;
					this->bit_directUDPCallback = (tag.GetInt()>>12)&0x01;
					this->bit_supportsCaptcha = (tag.GetInt()>>11)&0x01;
					this->bit_supportsSourceEx2 = (tag.GetInt()>>10)&0x01;
					this->bit_requiresCryptLayer = (tag.GetInt()>>9)&0x01;
					this->bit_requestsCryptLayer = (tag.GetInt()>>8)&0x01;
					this->bit_supportsCryptLayer = (tag.GetInt()>>7)&0x01;
					this->bit_extMultiPacket = (tag.GetInt()>>5)&0x01;
					this->bit_supportsLargeFiles = (tag.GetInt()>>4)&0x01;
					this->by_kadVersion = (uint8)((tag.GetInt()>>0)&0x0f);

					this->bit_requestsCryptLayer = this->bit_requestsCryptLayer & this->bit_supportsCryptLayer;
					this->bit_requiresCryptLayer = this->bit_requiresCryptLayer & this->bit_requestsCryptLayer;
				}
			}
			break;
		case CT_EMULE_VERSION:
			{
				if(tag.IsInt())
				{
					this->by_compatibleClient = (uint8)(tag.GetInt()>>24);
					this->u_clientVersion = tag.GetInt()&0x00ffffff;
					this->by_emuleVersion = 0x99;
					this->bit_sharedDirectories = 1;
					this->ul_emuleTags |= 4;
				}
			}
			break;
		case 0x69:
		case 0x6A:
		case 0x3D:
		case 0xEE:
		case 0x3E:
			this->nonofficialopcodes=true;
			break;
		default:
			DEBUG_PRINT1("Unknow tag");
		}
	}

	unsigned long serverIP = data.ReadUInt32();
	unsigned short serverPort = data.ReadUInt16();

	if(this->user_name.find("EMULE-CLIENT")!=string::npos || this->user_name.find("POWERMULE")!=string::npos)
	{
		b_gplEvildoer = true;
	}

	bool b_isMule = ((this->ul_emuleTags&0x04)==0x04);

	this->InitClientSoftwareVersion();
}


void FileClientSession::ProcessSecIdentStatePacket(SafeMemFile& data)
{	
	unsigned char* buffer = data.memBuffer;
	switch(buffer[0])
	{
	case 0:
		secureState = IS_UNAVAILABLE;
		break;
	case 1:
		secureState = IS_SIGNATURENEEDED;
		break;
	case 2:
		secureState = IS_KEYANDSIGNEEDED;
		break;
	}

	client_credit.cryptRndChallengeFrom = PeekUInt32(buffer+1);
}

boost::shared_ptr<Packet> FileClientSession::createSignaturePacket()
{	
	boost::shared_ptr<Packet> ret;
	
	if(client_credit.GetSecIDKeyLen() == 0 || secureState==0)
	{
		return ret;
	}

	if(client_credit.cryptRndChallengeFrom==0)
	{
		return ret;
	}
	bool bUseV2;
	if((by_supportSecIdent & 1) == 1)
		bUseV2 = false;
	else
		bUseV2 = true;

	uint8 by_chatIPKind = 0;
	uint32 challengeIP = 0;
	if(bUseV2)
	{
		DEBUG_PRINT1("No supported,no server connection \n");
		return ret;
	}
	unsigned char buffer[250];

	uint8 siglen = 0;
	siglen = creditsPool.CreateSignature(&client_credit,buffer,250,challengeIP,by_chatIPKind);
	if(siglen == 0)
		return ret;
	boost::shared_ptr<Packet> packet (new Packet(OP_SIGNATURE,siglen+1+(bUseV2?1:0),OP_EMULEPROT));
	memcpy(packet->pBuffer+1,buffer,siglen)	;
	packet->pBuffer[0] = siglen;
	if(bUseV2)
	{
		packet->pBuffer[1+siglen] = by_chatIPKind;
	}
	
	secureState = IS_ALLREQUESTSSEND;

	ret = packet;
	return ret;
}

boost::shared_ptr<Packet> FileClientSession::createPublicKeyPacket()
{
	boost::shared_ptr<Packet> packet(new Packet(OP_PUBLICKEY,creditsPool.GetPublicKeyLen()+1,OP_EMULEPROT));
	memcpy(packet->pBuffer+1,creditsPool.GetPublicKey(),creditsPool.GetPublicKeyLen());
	packet->pBuffer[0] = creditsPool.GetPublicKeyLen();
	secureState = IS_SIGNATURENEEDED;
	return packet;
}

boost::shared_ptr<Packet> FileClientSession::createSecIdentStatePacket()
{
	uint8 value = 0;
	if(client_credit.GetSecIDKeyLen()==0)
		value = IS_KEYANDSIGNEEDED;
	else 
		value = IS_SIGNATURENEEDED;

	uint32 u_random= rand()+1;
	client_credit.cryptRndChallengeFor = u_random;
	boost::shared_ptr<Packet> packet(new Packet(OP_SECIDENTSTATE,5,OP_EMULEPROT));
	packet->pBuffer[0] = value;
	PokeUInt32(packet->pBuffer+1,u_random);
	return packet;
}

