// Packet.h: interface for the Packet class.
//
//////////////////////////////////////////////////////////////////////

class Packet  
{
public:
	char* GetUDPHeader();
	bool UnPackPacket(UINT uMaxDecompressedSize);
	void PackPacket();
	Packet();
	Packet(uint8 protocol);
	Packet(char* header);
	Packet(char* datafile,uint32 datalength,uint8 protocol=OP_EDONKEYPROT,uint8 ucOpcode=0x00);
	Packet(uint8 opcode,uint32 size,uint8 protocol=OP_EDONKEYPROT,bool bfromPartFile=true);
	unsigned char* DetachPacket();
	char* GetHeader();
	virtual ~Packet();

	char* pBuffer;
	uint32 size;
	uint8 opcode;
	uint8 prot;
protected:
	bool m_bPacked;
	char* completebuffer;
	char* tempbuffer;
	char head[6];
};

