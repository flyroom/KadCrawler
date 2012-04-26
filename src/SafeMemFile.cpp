// SafeMemFile.cpp: implementation of the SafeMemFile class.
//
//////////////////////////////////////////////////////////////////////

#include "config.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

SafeMemFile::~SafeMemFile()
{
	free(memBuffer);
	memBuffer = NULL;
	memPos = 0;
	mem_size = 0;
	file_size = 0;
}

SafeMemFile::SafeMemFile(const uchar *buffer, uint32 len)
{
	memBuffer = NULL;
	if(buffer != NULL)
	{
		memBuffer = (BYTE*)malloc(sizeof(BYTE)*len);
	}

	if(memBuffer!=NULL)
	{
		memcpy(memBuffer,buffer,len*sizeof(BYTE));
	}
	memPos = 0;
	mem_size = len;
	file_size = len;
}

SafeMemFile::SafeMemFile(uint32 nGrowBytes)
{
	memBuffer = (BYTE*)malloc(sizeof(BYTE)*nGrowBytes);
	memPos=0;
	mem_size = nGrowBytes;
	file_size = 0;
}

bool SafeMemFile::CanReadByte()
{
	if(memPos+sizeof(uint8)>file_size)
		return false;
	return true;
}

uint16 SafeMemFile::GetAvailable()
{
	return (uint16)(file_size-memPos);
}

uint8 SafeMemFile::ReadUInt8()
{
	if(memPos+sizeof(uint8) > file_size)
		return 0;
	return *(memBuffer+memPos++);
}

void SafeMemFile::WriteUInt128(const CUInt128* pVal)
{
	if(memPos+sizeof(uint32)*4 > file_size)
	{
		memBuffer = (byte*)realloc(memBuffer,memPos+sizeof(uint32)*4);
		mem_size = memPos+sizeof(uint32)*4;
	}

	const uint32* pData = (uint32*)pVal->GetData();
	uint32* pUInt32Val = (uint32*)(memBuffer+memPos);
	pUInt32Val[0] = pData[0];
	pUInt32Val[1] = pData[1];
	pUInt32Val[2] = pData[2];
	pUInt32Val[3] = pData[3];

	memPos += sizeof(uint32)*4;
	if(memPos > file_size)
	{
		file_size = memPos;
	}
}

void SafeMemFile::ReadUInt128(CUInt128* pVal)
{
	if(memPos+sizeof(uint32)*4 > file_size)
	{
		return;
	}
	uint32* pUInt32Val = (uint32*)pVal->GetDataPtr();
	const uint32* pData = (uint32*)(memBuffer+memPos);
	pUInt32Val[0] = pData[0];
	pUInt32Val[1] = pData[1];
	pUInt32Val[2] = pData[2];
	pUInt32Val[3] = pData[3];
	memPos += sizeof(uint32)*4;
}

uint64 SafeMemFile::ReadUInt64()
{
	uint64 uRetVal;
	ReadByteArray((char*)&uRetVal,sizeof(uint64));
	return uRetVal;
}

uint32 SafeMemFile::ReadUInt32()
{
	if(memPos+sizeof(uint32) > file_size)
	{
		return 0;
	}
	uint32 nResult = *((uint32*)(memBuffer+memPos));
	memPos += sizeof(uint32);
	return nResult;
}

uint16 SafeMemFile::ReadUInt16()
{
	if(memPos+sizeof(uint16) > file_size)
	{
		return 0;
	}
	uint16 nResult = *((uint16*)(memBuffer+memPos));
	memPos += sizeof(uint16);
	return nResult;
}

float SafeMemFile::ReadFloat()
{
	float fRetVal;
	ReadByteArray((char*)&fRetVal,sizeof(float));
	return fRetVal;
}

BYTE* SafeMemFile::ReadBsob(uint8* puSize)
{
	*puSize = ReadUInt8();
	if(GetAvailable() < *puSize)
		return NULL;
	BYTE* pBuf = new BYTE[*puSize];

	ReadByteArray((char*)pBuf,*puSize);
	return pBuf;
}

void SafeMemFile::WriteUInt8(uint8 nVal)
{
	if(memPos+sizeof(uint8) > mem_size)
	{
		memBuffer = (byte*)realloc(memBuffer,memPos+sizeof(uint8));
		mem_size += sizeof(uint8);
	}
	*(memBuffer+memPos++)  = nVal;
	if(memPos > file_size)
		file_size = memPos;
}

void SafeMemFile::WriteUInt16(uint16 nVal)
{
	if(memPos+sizeof(uint16) > mem_size)
	{
		memBuffer = (byte*)realloc(memBuffer,memPos+sizeof(uint16));
		mem_size += sizeof(uint16);
	}
	*((uint16*)(memBuffer+memPos))  = nVal;
	memPos += sizeof(uint16);
	if(memPos > file_size)
		file_size = memPos;
}

void SafeMemFile::WriteUInt32(uint32 nVal)
{
	if(memPos+sizeof(uint32) > mem_size)
	{
		memBuffer = (byte*)realloc(memBuffer,memPos+sizeof(uint32));
		mem_size += sizeof(uint32);
	}
	*((uint32*)(memBuffer+memPos))  = nVal;
	memPos += sizeof(uint32);
	if(memPos > file_size)
		file_size = memPos;
}

void SafeMemFile::WriteUInt64(uint64 nVal)
{
	if(memPos+sizeof(uint64) > mem_size)
	{
		memBuffer = (byte*)realloc(memBuffer,memPos+sizeof(uint64));
		mem_size += sizeof(uint64);
	}
	*((uint64*)(memBuffer+memPos))  = nVal;
	memPos += sizeof(uint64);
	if(memPos > file_size)
		file_size = memPos;
}

string SafeMemFile::ReadString()
{
	char raw_string[1024]={0};
	uint16 raw_size = ReadUInt16();
	ReadByteArray(raw_string,raw_size);
	wstring converted;
	string val = ws2s(UTF2Uni(raw_string,converted));
	return val;
}

void SafeMemFile::ReadTagList(TagList* pTagList)
{
	uint32 uCount = ReadUInt8();
	for(uint32 i=0;i<uCount;i++)
	{
		KadTag* pTag = ReadTag();
		pTagList->push_back(pTag);
	}
}

KadTag* SafeMemFile::ReadTag()
{
	KadTag* pRetVal = NULL;
	byte byType = 0;
	uint16 uLenName = 0;
	char *pcName = NULL;

	byType = ReadUInt8();
	uLenName = ReadUInt16();
	pcName = new char[uLenName+1];
	memset(pcName,0,uLenName+1);

	ReadByteArray(pcName,uLenName);
	switch(byType)
	{
	case TAGTYPE_HASH:
		{
			BYTE byValue[16];
			ReadByteArray((char*)byValue,16);
			pRetVal = new KadTagHash(pcName,byValue);
			break;
		}
	case TAGTYPE_STRING:
		{
			char raw_string[1024]={0};
			uint16 raw_size = ReadUInt16();
			ReadByteArray(raw_string,raw_size);
			wstring converted;
			string val = ws2s(UTF2Uni(raw_string,converted));
			pRetVal = new KadTagStr(pcName,(char*)val.c_str());
			break;
		}
	case TAGTYPE_UINT64:
		{
			pRetVal = new KadTagUInt64(pcName,ReadUInt64());
			break;
		}
	case TAGTYPE_UINT32:
		{
			pRetVal = new KadTagUInt32(pcName,ReadUInt32());
			break;
		}
	case TAGTYPE_UINT16:
		{
			pRetVal = new KadTagUInt16(pcName,ReadUInt16());
			break;
		}
	case TAGTYPE_UINT8:
		{
			pRetVal = new KadTagUInt8(pcName,ReadUInt8());
			break;
		}
	case TAGTYPE_FLOAT32:
		{
			pRetVal = new KadTagFloat(pcName,ReadFloat());
			break;
		}
	case TAGTYPE_BSOB:
		{
			uint8 size;
			BYTE* buf = ReadBsob(&size);
			pRetVal = new KadTagBsob(pcName,buf,size);
			break;
		}
	default:
		DEBUG_PRINT2("unidentified tag type: %02lX\n",(ULONG)byType);
		break;
	}

	delete[] pcName;
	pcName = NULL;
	return pRetVal;
}

void SafeMemFile::ReadByteArray(char* buffer,uint16 bufLen)
{
	for(int i=0;i<bufLen;i++)
	{
		if(!CanReadByte())
			break;
		buffer[i]=ReadUInt8();
	}
}

void SafeMemFile::WriteByteArray(const char* buffer,uint32 nByteCount)
{
	if(memPos+sizeof(uint8)*nByteCount > mem_size)
	{
		memBuffer = (byte*)realloc(memBuffer,memPos+sizeof(uint8)*nByteCount);
		mem_size += sizeof(uint8)*nByteCount;
	}
	memcpy(memBuffer+memPos,buffer,nByteCount);
	memPos+=nByteCount;
	if(memPos > file_size)
		file_size = memPos;
}

void SafeMemFile::WriteTag(const KadTag* pTag)
{
	uint8 uType;
	if(pTag->m_type == 0xFE)
	{
		if(pTag->GetInt() <= 0xFE)
			uType = TAGTYPE_UINT8;
		else if(pTag->GetInt() <= 0xFFFF)
			uType = TAGTYPE_UINT16;
		else if(pTag->GetInt() <= 0xFFFFFFFF)
			uType = TAGTYPE_UINT32;
		else
			uType = TAGTYPE_UINT64;
	}
	else
		uType = pTag->m_type;

	WriteUInt8(uType);
	string name = pTag->m_name;
	WriteUInt16((uint16)name.length());
	WriteByteArray(name.c_str(),name.length());

	switch(uType)
	{
	case TAGTYPE_HASH:
		WriteByteArray((const char*)pTag->GetHash(),16);
		break;
	case TAGTYPE_STRING:
		{
			string unicodeStr = s2utfs(pTag->GetStr());;
			WriteUInt16(unicodeStr.length());
			WriteByteArray(unicodeStr.c_str(),unicodeStr.length());
		}
		break;
	case TAGTYPE_UINT64:
		{
			WriteUInt64(pTag->GetInt());
		}
		break;
	case TAGTYPE_UINT32:
		{
			WriteUInt32((uint32)pTag->GetInt());
		}
		break;
	case TAGTYPE_UINT16:
		{
			WriteUInt16((uint16)pTag->GetInt());
		}
		break;
	case TAGTYPE_UINT8:
		{
			WriteUInt8((uint8)pTag->GetInt());
		}
		break;
	case TAGTYPE_FLOAT32:
		{
			
		}
		break;
	case TAGTYPE_BSOB:
		{
			WriteByteArray((const char *)pTag->GetBsob(),pTag->GetBsobSize());
		}
		break;
	}
}

void SafeMemFile::WriteTagList(const TagList& tagList)
{
	uint32 uCount = tagList.size();
	WriteUInt8((uint8)uCount);
	for(TagList::const_iterator itTagList = tagList.begin();itTagList != tagList.end();itTagList++)
	{
		WriteTag(*itTagList);
	}
}
