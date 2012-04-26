

class SafeMemFile  
{
public:
	SafeMemFile(const uchar* buffer,uint32 len);
	SafeMemFile(uint32 nGrowBytes = 512);
	virtual ~SafeMemFile();

	void WriteUInt128(const CUInt128* pVal);
	void WriteUInt8(uint8 nVal);
	void WriteUInt16(uint16 nVal);
	void WriteUInt32(uint32 nVal);
	void WriteUInt64(uint64 nVal);
	void WriteByteArray(const char* buffer,uint32 nByteCount);

	bool CanReadByte();
	uint16 GetAvailable();
	void ReadUInt128(CUInt128* pVal);
	uint64 ReadUInt64();
	uint32 ReadUInt32();
	uint16 ReadUInt16();
	uint8 ReadUInt8();
	float ReadFloat();
	void ReadByteArray(char* buffer,uint16 bufLen);
	string ReadString();
	BYTE* ReadBsob(uint8* puSize);

	void ReadTagList(TagList* pTagList);
	KadTag* ReadTag();

	void WriteTag(const KadTag* pTag);
	void WriteTagList(const TagList& tagList);
	
	BYTE* memBuffer;
	uint32 memPos;
	uint32 mem_size;
	uint32 file_size;
};

