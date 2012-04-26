/********************************************************************************
Module Name : CIpInfo
Description : a simple class to operate the QQwry data file
Author      : orbit (inte2000@163.com)
Date        : March 17th, 2005
********************************************************************************/
#include "config.h"
#include "QQIpInfo.h"


const int nIpRecordCound = 7;//first 4 bytes is IP(host byte order),last 3 bytes is offset of IP infor 

const char* lpszBoradCast = "broadcast address";
const char* lpszUnknow = ("unknow address");

const int IP_SIZE=4;
const int OFFSET_SIZE=3;
const int INDEX_RECORD_SIZE = IP_SIZE + OFFSET_SIZE;

enum REDIRECT_MODE
{
    REDIRECT_MODE_1=0x01,
    REDIRECT_MODE_2=0x02
};

CIpInfo::CIpInfo()
{
	m_pDataBuffer = NULL;
	m_dwRecordCount = 0;
	m_bInit = false;
}

CIpInfo::CIpInfo(char* lpszFilePathName)
{
	LoadInfoFile(lpszFilePathName);
}

CIpInfo::~CIpInfo()
{
	FreeBuffer();
}

bool CIpInfo::IsInitialed()
{
	return m_bInit && (m_pDataBuffer != NULL);
}

bool CIpInfo::LoadInfoFile(const char* lpszFilePathName)
{
	bool bReturn = false;

	ifstream hSrcFile(lpszFilePathName,ios_base::binary);
	if(hSrcFile.is_open()&& !hSrcFile.fail())
	{
        hSrcFile.seekg(0,ios::end);
		unsigned long dwNumberOfBytesToRead = hSrcFile.tellg();//Get file size
        hSrcFile.seekg(0,ios::beg);
		m_pDataBuffer = new unsigned char[dwNumberOfBytesToRead + 1];//would not be failed in win32?
        memset(m_pDataBuffer,0,dwNumberOfBytesToRead+1);
		if(m_pDataBuffer != NULL)
		{
			hSrcFile.read((char*)m_pDataBuffer,dwNumberOfBytesToRead);
            unsigned long readBytes = hSrcFile.gcount();
            if(readBytes > 0)
			{
				//calculate the ip information record count
				unsigned long *pIntData = (unsigned long *)m_pDataBuffer;
				unsigned long nBuffer_0 = *pIntData;//Start position of record infor in file
				unsigned long nBuffer_4	= *(pIntData + 1);//End position of record infor in file
                first_index_pos = *pIntData;
                last_index_pos= *(pIntData+1);

				nBuffer_4 -= nBuffer_0;
				
				m_dwRecordCount = nBuffer_4 / 7;//IP record count
				int nsuiv = nBuffer_4 % 7;
				if(nsuiv == 0)//must be integral info struct,7 bytes
				{
					m_bInit = true;
					bReturn = m_bInit;
				}
			}
			if(hSrcFile.fail())
			{
				DEBUG_PRINT1("Error Opening File\n");
			}
            if(hSrcFile.bad())
			{
				DEBUG_PRINT1("Error reading File\n");
			}
            while(readBytes < dwNumberOfBytesToRead && hSrcFile.eof())
            {
                hSrcFile.read((char*)(m_pDataBuffer+readBytes),dwNumberOfBytesToRead-readBytes);
                unsigned long cur_read = hSrcFile.gcount();
                readBytes += cur_read;
            }
		}
		hSrcFile.close();//close IP data file
	}
	if(!m_bInit)
			FreeBuffer();//Verify the null buffer if we got some error

	return bReturn;
}

string readString(unsigned char* buffer,const int offset_param)
{
    std::ostringstream stream;
    unsigned int offset = offset_param;
    unsigned char* pBuffer = buffer+offset;
    unsigned char byte = *(pBuffer);
    while(byte != 0 && byte != EOF)
    {
        stream<<byte;
        offset++;
        byte = *(buffer+offset);
    }
    return stream.str();
}
string readAreaAddr(unsigned char* buffer,int offset=0)
{
    char b=0;
    memcpy(&b,buffer+offset,sizeof(char));
    offset++;
    if(b == REDIRECT_MODE_1 || b == REDIRECT_MODE_2)
    {
        int areaOffset=0;
        memcpy(&areaOffset,buffer+offset,sizeof(char)*3);
        if(areaOffset)
            return readString(buffer,areaOffset);
        else
            return "Unknown";
    }
    else
    {
        offset--;
        return readString(buffer,offset);
    }
}

string CIpInfo::GetIpInfo(unsigned long ip)
{
	unsigned char *ipBuffer = (unsigned char *)m_pDataBuffer;
    string address;
        
    unsigned long size = m_dwRecordCount;
    unsigned long left = 0;
    unsigned long right = size-1;

    while(true)
    {
        if(right-left==1)
            break;
        unsigned long mid = (left+right)/2; 
        
        int tempOffset = first_index_pos + mid*INDEX_RECORD_SIZE;
        unsigned long tempIP;
        memcpy(&tempIP,ipBuffer+tempOffset,sizeof(unsigned long));
        if(ip >= tempIP)
        {
            left = mid;
        }
        else
        {
            right = mid;
        }
    }
    unsigned long pos = left;
    unsigned long index_offset = first_index_pos + pos*INDEX_RECORD_SIZE+4;
    unsigned long addr_offset=0; 
    memcpy(&addr_offset,ipBuffer+index_offset,3*sizeof(unsigned char));
     
    char type=0;
    unsigned long current_pos = addr_offset+4;
    memcpy(&type,ipBuffer+current_pos,sizeof(unsigned char));
    current_pos++;
    if(type == REDIRECT_MODE_1)
    {
        int countryOffset = 0;
        memcpy(&countryOffset,ipBuffer+current_pos,3*sizeof(char));
        current_pos += 3; 

        current_pos = countryOffset;
        char r_type=0;
        memcpy(&r_type,ipBuffer+current_pos,sizeof(char));
        current_pos++;

        if(r_type == REDIRECT_MODE_2)
        {
            int p = 0;
            memcpy(&p,ipBuffer+current_pos,3*sizeof(char));
            address = readString(ipBuffer,p);            
            current_pos = countryOffset+4;
        }
        else
        {
            address = readString(ipBuffer,countryOffset);
            current_pos = countryOffset+address.size()+1;
        }

        address.append(" ");
        address.append(readAreaAddr(ipBuffer,current_pos));         
    }
    else if(type == REDIRECT_MODE_2)
    {
        int p=0;
        memcpy(&p,ipBuffer+current_pos,sizeof(char)*3);
        address = readString(ipBuffer,p);
        address.append(" ");
        address.append(readAreaAddr(ipBuffer,addr_offset+8));
    }
    else
    {
        current_pos--;
        address = readString(ipBuffer,current_pos);
        current_pos += address.size()+1;
        address.append(" ");
        address.append(readAreaAddr(ipBuffer,current_pos)); 
    }

    return address;
}


bool CIpInfo::GetIpInfo(unsigned char* lpszDotIp,unsigned char* lpszInfoBuf,int nMaxBufSize)
{
	bool bReturn = false;
	lpszInfoBuf[0] = '\0';
	if(m_bInit)
	{
		unsigned long lHostByteOrderAddr = inet_addr((char*)lpszDotIp);
		if(lHostByteOrderAddr != INADDR_NONE)
		{
			unsigned long lNetByteOrderAddr = htonl(lHostByteOrderAddr);
			bReturn = GetIpInfo(lNetByteOrderAddr,lpszInfoBuf,nMaxBufSize);
		}
	}
	return bReturn;
}	

bool CIpInfo::GetIpInfo(unsigned long uIP ,unsigned char* lpszInfoBuf,int nMaxBufSize)
{
	lpszInfoBuf[0] = '\0';
	if(uIP == (unsigned long)-1)//BoradCast IP
	{
		strcpy((char*)lpszInfoBuf,lpszBoradCast);
		return true;
	}

	unsigned char* lpszPosition = lpszInfoBuf;
	unsigned long *pIntData = (unsigned long *)m_pDataBuffer;
	unsigned long nBuffer_0 = *pIntData;
	unsigned char *pesi = m_pDataBuffer + nBuffer_0;
	unsigned char *pData = pesi + m_dwRecordCount * 7 + 4;
	pIntData = (unsigned long *)pData;
	unsigned long nedx = *pIntData;
	nedx &= 0xFFFFFF;
	
	pIntData = (unsigned long *)(m_pDataBuffer + nedx);
	if(uIP <= *pIntData)
	{
		unsigned long nLowIdx = 0;
		unsigned long nUpIdx;
		unsigned long nTotal = m_dwRecordCount;
		//binary search
		while(true)
		{
			nUpIdx = nTotal - 1;
			if(nLowIdx >= nUpIdx)
				break;

			nUpIdx = nTotal + nLowIdx;
			nUpIdx >>= 1;
			pIntData = (unsigned long *)(pesi + nUpIdx * 7);
			if(uIP >= *pIntData)
				nLowIdx = nUpIdx;
			else
				nTotal = nUpIdx;
		}

		unsigned long dwEdx = nLowIdx * 7;
		pData = pesi + dwEdx + 4;
		pIntData = (unsigned long *)pData;
		nedx = *pIntData;//pedx---esi
		nedx &= 0xFFFFFF;
		pIntData = (unsigned long *)(m_pDataBuffer + nedx);
		char sign;
		int cccc;
		if(uIP <= *pIntData)
		{
			pData = m_pDataBuffer + nedx + 4;
			sign = *pData;
			if(sign != 0x01)
			{
				nedx += 4;
				unsigned long dwdddd;//eax
				if(sign == 0x02)
				{
					pData = m_pDataBuffer + nedx + 1;
					pIntData = (unsigned long *)pData;
					dwdddd = *pIntData;
					dwdddd &= 0xFFFFFF;
					cccc = 3;
					dwEdx = cccc;
				}
				else
				{
					dwdddd = nedx;
					cccc = 0;
					if(sign	== 0x00)
					{
						dwEdx = cccc;
					}
					else
					{
						unsigned char *pEdi;
						unsigned char *psss;
						do
						{
							dwEdx = ++cccc;
							unsigned long off = cccc;
							off &= 0xFF;
							pEdi = m_pDataBuffer + off;
							psss = pEdi + nedx;
						}
						while(*psss != 0);
					}
				}
				pData = m_pDataBuffer + dwdddd;
				while(*pData != 0)
				{
					*lpszPosition++ = *pData++;
				}
				dwEdx &= 0xFF;
				dwdddd = nedx + dwEdx + 1;
				pData = m_pDataBuffer + dwdddd;
				if(*pData == 0x02)
				{
					pData = m_pDataBuffer + dwdddd + 1;
					pIntData = (unsigned long *)pData;
					dwdddd = *pIntData;
					dwdddd &= 0xFFFFFF;
				}

				pData = m_pDataBuffer + dwdddd;
				while(*pData != 0)
				{
					*lpszPosition++ = *pData++;
				}
				*lpszPosition = 0;
				
				return true;
			}
			else//sign==1
			{
				pData = m_pDataBuffer + nedx + 5;//nedx---esi
				pIntData = (unsigned long *)pData;
				unsigned long dwData = *pIntData;//eax
				dwData &= 0xFFFFFF;
				pData = m_pDataBuffer + dwData;
				char dl = *pData;
				pData = m_pDataBuffer + dwData + 1;
				pIntData = (unsigned long *)pData;
				unsigned long dwEdi = *pIntData;
				dwEdi &= 0xFFFFFF;//edi
				cccc = 3;
				unsigned long dwEsi = cccc;
				if(dl != 2)
				{
					cccc = 0;
					dwEdi = dwData;
					if(dl == 0)
						dwEsi = cccc;
					else
					{
						unsigned char *pEdi;
						unsigned char *psss;
						do
						{
							dwEsi = ++cccc;
                            if(cccc>1000)
                                break;
							unsigned long off = cccc;
							off &= 0xFF;
							pEdi = m_pDataBuffer + off;
							psss = pEdi + nedx;
						}while(*psss != 0);
					}
				}

				pData = m_pDataBuffer + dwEdi;
				//copy ip address info to dword_10009B0C
				while(*pData != 0)
				{
					*lpszPosition++ = *pData++;
				}

				dwData += cccc + 1;// reposition
				pData = m_pDataBuffer + dwData;
				if(*pData == 0x02)//if equalals 2,shift one byte afterwards to locate the additional info of ip
				{
					pData = m_pDataBuffer + dwData + 1;
					pIntData = (unsigned long *)pData;
					dwData = *pIntData;
					dwData &= 0xFFFFFF;//edi
					pData = m_pDataBuffer + dwData;
				}
				//copy ip address additional info to dword_10009B10
				while(*pData != 0)
				{
					*lpszPosition++ = *pData++;
				}
				*lpszPosition = 0;

				return true;
			}
		}
	}
	
	strcpy((char*)lpszInfoBuf,lpszUnknow);//unknow IP
	return false;
}

void CIpInfo::FreeBuffer()
{
	if(m_pDataBuffer != NULL)
		delete []m_pDataBuffer;

	m_pDataBuffer = NULL;
	m_dwRecordCount = 0;
	m_bInit = false;
}
