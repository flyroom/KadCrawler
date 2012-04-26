/********************************************************************************
Module Name : CIpInfo
Description : a simple class to operate the QQwry data file
Author      : orbit (inte2000@163.com)
Date        : March 17th, 2005
********************************************************************************/
#ifndef __IPINFO_H__
#define __IPINFO_H__

class CIpInfo
{
public:
	CIpInfo();
	CIpInfo(char* lpszFilePathName);
	~CIpInfo();
public:
	bool IsInitialed();
	bool LoadInfoFile(const char* lpszFilePathName);
    bool GetIpInfo(unsigned long uIP,unsigned char* lpszInfoBuf,int nMaxBufSize);// retrieve by net order ip address
	bool GetIpInfo(unsigned char* lpszDotIp,unsigned char* lpszInfoBuf,int nMaxBufSize);//retrieve by dotted ip address
    string GetIpInfo(unsigned long ip);
	unsigned long GetRecordCount() const { return m_dwRecordCount; };
	void FreeBuffer();
protected:
	unsigned char* m_pDataBuffer;
	unsigned long m_dwRecordCount;
	bool m_bInit;

private:
    unsigned long first_index_pos;
    unsigned long last_index_pos;
};


#endif //__IPINFO_H__
