#pragma once

class YTag
{
public:
	YTag(string name,string val)
	{
		m_type = TAGTYPE_STRING;
		m_uName = 0;
		m_sName = name;
		m_BlobSize = 0;
		m_sVal = new string(val);
	}
	YTag(uint8 uName,string val)
	{
		m_type = TAGTYPE_STRING;
		m_uName = uName;
		m_sVal = new string(val);
		m_sName = "";
		m_BlobSize = 0;
	}

	YTag(uint8 uName,uint64 uVal,bool bInt64=false)
	{
		if(bInt64)
			m_type = TAGTYPE_UINT64;
		else 
			m_type = TAGTYPE_UINT32;
		m_uVal = uVal;
		m_uName = uName;
		m_sName="";
		m_BlobSize=0;
	}

	~YTag()
	{
		if(IsStr())
			delete m_sVal;
		else if(IsHash())
			delete[] m_pVal;
		else if(IsBlob())
			delete[] m_pVal;
	}

	YTag(SafeMemFile& data)
	{
		m_type = data.ReadUInt8();
		if( m_type &0x80)
		{
			m_type = 0x7F;
			m_uName = data.ReadUInt8();
			m_sName = "";
		}
		else
		{
			UINT length = data.ReadUInt16();
			if(length == 1)
			{
				m_uName = data.ReadUInt8();
				m_sName = "";
			}
			else
			{
				m_uName = 0;
				char* tempBuf = new char[length+1];
				data.ReadByteArray(tempBuf,length);
				tempBuf[length]=0;
				m_sName = tempBuf;
				delete[] tempBuf;
			}
		}

		m_BlobSize = 0;
		if(m_type == TAGTYPE_STRING)
		{
			m_sVal = new string(data.ReadString());
		}
		else if(m_type == TAGTYPE_UINT32)
		{
			m_uVal = data.ReadUInt32();
		}
		else if(m_type == TAGTYPE_UINT64)
		{
			m_uVal = data.ReadUInt64();
		}
		else if(m_type == TAGTYPE_UINT16)
		{
			m_type = TAGTYPE_UINT32;
			m_uVal = data.ReadUInt16();
		}
		else if(m_type == TAGTYPE_UINT8)
		{
			m_type = data.ReadUInt8();
			m_type = TAGTYPE_UINT32;
		}
		else if(m_type == TAGTYPE_FLOAT32)
		{
			data.ReadByteArray((char*)&m_fVal,sizeof(float));
		}
		else if(m_type == TAGTYPE_BLOB)
		{
			m_BlobSize = data.ReadUInt32();
			m_pVal = new BYTE[m_BlobSize];
			data.ReadByteArray((char*)m_pVal,m_BlobSize);
		}
		else
		{
			m_uVal = 0;
		}
	}

	bool IsStr() const {	return m_type == TAGTYPE_STRING; }
	bool IsInt() const {	return m_type == TAGTYPE_UINT32; }
	bool IsFloat() const {	return m_type == TAGTYPE_FLOAT32;}
	bool IsHash() const { return m_type == TAGTYPE_HASH;}
	bool IsBlob() const { return m_type == TAGTYPE_BLOB;}
	bool IsInt64(bool bOrInt32=true) const { return m_type==TAGTYPE_UINT64||(IsInt()&&bOrInt32);};

	UINT GetNameID() const { return m_uName;}

	uint32 GetInt() const {return (uint32)m_uVal;}
	const string GetStr() const { return *m_sVal;}
	float GetFloat() const { return m_fVal;}

	bool WriteTagToFile(SafeMemFile* file) const
	{
		if(file == NULL)
			return false;
		if(IsStr()||IsInt()||IsFloat()||IsBlob()||IsInt64())
		{
			file->WriteUInt8(m_type);
			if(m_sName != "")
			{
				uint8 tagLen = m_sName.size();
				file->WriteByteArray(m_sName.c_str(),tagLen);
			}
			else
			{
				file->WriteUInt16(1);
				file->WriteUInt8(m_uName);
			}
			if(IsStr())
			{
				file->WriteUInt16(m_sVal->size());
				file->WriteByteArray(m_sVal->c_str(),m_sVal->size());
			}
			else if(IsInt())
			{
				file->WriteUInt32((uint32)m_uVal);
			}
			else if(IsInt64(false))
			{
				file->WriteUInt64(m_uVal);
			}
			else if(IsFloat())
			{
				file->WriteByteArray((char*)&m_fVal,4);
			}
			else if(IsBlob())
			{
				file->WriteUInt32(m_BlobSize);
			}
			else
				return false;
			return true;
		}
		else
			return false;
	}

protected:
	uint8 m_type;
	uint8 m_uName;
	string m_sName;
	uint32 m_BlobSize;
	union{
		string*  m_sVal;
		uint64  m_uVal;
		float	m_fVal;
		unsigned char* m_pVal;
	};
};

typedef struct _userkey_hash
{
	unsigned char hash[16];
	bool operator < (const struct _userkey_hash other) const
	{
		for(int i=0;i<16;i++)
		{
			if(hash[i]==other.hash[i])
				continue;
			else
				return hash[i]<other.hash[i];
		}
		return false;
	}
}userkey_hash;

class FileClientSession
{
public:
	FileClientSession(void);
	~FileClientSession(void);
	
	unsigned long ipaddr;

	userkey_hash user_hash;
	unsigned long user_id_hybrid;
	unsigned short user_port;

	bool b_isHybrid;

	string user_name;
	uint16 user_port_mod;
	string mod_version;

	uint16 kad_port;
	uint16 udp_port;

	uint32 buddy_ip;
	uint32 buddy_port;

	_EClientSoftware client_softversion;

	// emule misc option 1
	float f_supportsAICH;
	bool b_unicodeSupport;
	BYTE by_udpVersion;
	BYTE by_dataCompVer;
	BYTE by_supportSecIdent;
	BYTE by_sourceExchange1Ver;
	BYTE by_extendedRequestsVer;
	BYTE by_acceptCommentVer;
	float f_peerCache;
	float f_noViewSharedFiles;
	bool b_multiPacket;
	float f_supportsPreview;
	unsigned long ul_emuleTags;

	unsigned char by_kadVersion;

	// emule version
	unsigned char by_compatibleClient;
	string str_software;
	UINT u_clientVersion;
	unsigned char by_emuleVersion;

	bool b_gplEvildoer;

	bool nonofficialopcodes;

	// Secure Ident related
	_ESecureIdentState secureState;
	
	KadClientCredits client_credit;
	
	uint32	bit_hashsetRequestingMD4 : 1,
			bit_sharedDirectories:1,
			bit_sentCancelTransfer:1,
			bit_noViewSharedFiles:1,
			bit_supportsPreview:1,
			bit_previewReqPending:1,
			bit_previewAnsPending:1,
			bit_isSpammer:1,
			bit_messageFiltered:1,
			bit_peerCache:1,
			bit_queueRankPending:1,
			bit_unaskQueueRankRecv:2,
			bit_failedFileIdReqs:4,
			bit_needOurPublicIP:1,
			bit_supportsAICH:3,
			bit_AICHRequested:1,
			bit_sentOutOfPartReqs:1,
			bit_supportsLargeFiles:1,
			bit_extMultiPacket:1,
			bit_requestsCryptLayer:1,
			bit_supportsCryptLayer:1,
			bit_requiresCryptLayer:1,
			bit_supportsSourceEx2:1,
			bit_supportsCaptcha:1,
			bit_directUDPCallback:1,
			bit_supportsFileIdent:1;

	void InitClientSoftwareVersion();
	int GetHashType();
	void processHelloAnswer(SafeMemFile& data);
	void ProcessSecIdentStatePacket(SafeMemFile& data);

	boost::shared_ptr<Packet> createSignaturePacket();
	boost::shared_ptr<Packet> createPublicKeyPacket();
	boost::shared_ptr<Packet> createSecIdentStatePacket();
};
