// Packet.cpp: implementation of the Packet class.
//
//////////////////////////////////////////////////////////////////////

#include "config.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
#pragma pack(1)
struct Header_Struct{
	uint8 eDonkeyID;
	uint32 packetlength;
	uint8 command;
};

struct UDP_Header_Struct{
	uint8 eDonkeyID;
	uint8 command;
};

Packet::Packet()
{
	
}

Packet::~Packet()
{
	if(completebuffer)
		delete[] completebuffer;
	else
		delete[] pBuffer;
}

Packet::Packet(uint8 protocol)
{
	this->pBuffer = NULL;
	this->completebuffer = NULL;
	this->tempbuffer = NULL;
	this->m_bPacked = false;
	this->opcode = 0x00;
	this->prot = protocol;
}

Packet::Packet(char* header)
{
	this->pBuffer = NULL;
	this->completebuffer = NULL;
	this->tempbuffer = NULL;
	this->m_bPacked = false;
	Header_Struct *head = (Header_Struct*)header;
	size = head->packetlength-1;
	opcode = head->command;
	prot = head->eDonkeyID;
}

Packet::Packet(char* data,uint32 datalength,uint8 protocol,uint8 ucOpcode)
{
	size = datalength;

	completebuffer = new char[datalength+10];
	pBuffer = completebuffer+6;
	memcpy(pBuffer,data,size);

	this->prot = protocol;
	this->opcode = ucOpcode;
}

Packet::Packet(uint8 in_opcode,uint32 in_size,uint8 protocol,bool bfromPartFile)
{
	if(size)
	{
		completebuffer = new char[in_size+10];
		pBuffer = completebuffer + 6;
		memset(completebuffer,0,in_size+10);
	}
	else
	{
		pBuffer = 0;
		completebuffer = 0;
	}
	opcode = in_opcode;
	size = in_size;
	prot = protocol;
}

char* Packet::GetHeader()
{
	Header_Struct* header = (Header_Struct*)head;
	header->command = opcode;
	header->eDonkeyID = prot;
	header->packetlength= size+1;
	return (char*)header;
}

unsigned char* Packet::DetachPacket()
{
	if(completebuffer)
	{
		memcpy(completebuffer,GetHeader(),6);
		unsigned char* result=(unsigned char*)completebuffer;
		completebuffer=0;
		pBuffer=0;
		return result;
	}
	return NULL;
}

void Packet::PackPacket()
{
	/*
	ULONG newsize = size+300;
	BYTE* output = new BYTE[newsize];
	UINT32 result = compress2(output,&newsize,(BYTE*)pBuffer,size,Z_BEST_COMPRESSION);
	if(result != Z_OK || size <= newsize)
	{
		delete[] output;
		return;
	}

	if(prot == OP_KADEMLIAHEADER)
	{
		prot = OP_KADEMLIAPACKEDPROT;
	}
	else
		prot = OP_PACKEDPROT;

	memcpy(pBuffer,output,newsize);

	size = newsize;
	delete[] output;
	m_bPacked = true;
	*/
}

bool Packet::UnPackPacket(UINT uMaxDecompressedSize)
{
	/*
	uint32 nNewSize = size*10+300;
	if(nNewSize > uMaxDecompressedSize)
	{
		nNewSize = uMaxDecompressedSize;
	}

	BYTE* unpack = NULL;
	ULONG unpackedsize = 0;
	uint32 result = 0;
	do 
	{
		delete[] unpack;
		unpack = new BYTE[nNewSize];
		unpackedsize = nNewSize;
		result = uncompress(unpack,&unpackedsize,(BYTE*)pBuffer,size);
		nNewSize *= 2;
	} while (result == Z_BUF_ERROR && nNewSize < uMaxDecompressedSize);

	if(result == Z_OK)
	{
		size = unpackedsize;
		delete[] pBuffer;
		pBuffer = (char*)unpack;
		if(prot == OP_KADEMLIAPACKEDPROT)
			prot = OP_KADEMLIAHEADER;
		else
			prot = OP_EMULEPROT;
		return false;
	}

	delete[] unpack;
	return false;
	*/
	return false;
}

char* Packet::GetUDPHeader()
{
	UDP_Header_Struct* header = (UDP_Header_Struct*)head;
	header->command = opcode;
	header->eDonkeyID = prot;
	return head;
}
