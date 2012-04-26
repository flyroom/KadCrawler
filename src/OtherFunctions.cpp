#include"config.h"

#ifndef WIN32
typedef wchar_t WCHAR;
#endif

static void swap_byte (uint8* a, uint8* b){
	uint8 bySwap;
	bySwap = *a;
	*a = *b;
	*b = bySwap;
}

RC4_Key_Struct* RC4CreateKey(const uchar* pachKeyData,uint32 nLen,RC4_Key_Struct* key,bool bSkipDiscard)
{
	uint8 index1;
	uint8 index2;
	uint8* pabyState;
	
	if (key == NULL)
		key = new RC4_Key_Struct;
	
	pabyState= &key->abyState[0];
	for (int i = 0; i < 256; i++)
		pabyState[i] = (uint8)i;
	
	key->byX = 0;
	key->byY = 0;
	index1 = 0;
	index2 = 0;
	for (int i = 0; i < 256; i++){
		index2 = (pachKeyData[index1] + pabyState[i] + index2);
		swap_byte(&pabyState[i], &pabyState[index2]);
		index1 = (uint8)((index1 + 1) % nLen);
	}
	if (!bSkipDiscard)
		RC4Crypt(NULL, NULL, 1024, key);
	return key;
}

void RC4Crypt(const uchar* pachIn,uchar* pachOut,uint32 nLen,RC4_Key_Struct* key)
{
	if (key == NULL)
		return;
	
	uint8 byX = key->byX;;
	uint8 byY = key->byY;
	uint8* pabyState = &key->abyState[0];;
	uint8 byXorIndex;
	
	for (uint32 i = 0; i < nLen; i++)
	{
		byX = (byX + 1);
		byY = (pabyState[byX] + byY);
		swap_byte(&pabyState[byX], &pabyState[byY]);
		byXorIndex = (pabyState[byX] + pabyState[byY]);
		
		if (pachIn != NULL)
			pachOut[i] = pachIn[i] ^ pabyState[byXorIndex];
    }
	key->byX = byX;
	key->byY = byY;
}

string ipstr(uint32 nIP)
{
	const BYTE* pucIP = (BYTE*)&nIP;
	std::ostringstream stream;
	stream<<pucIP[0]<<"."<<pucIP[1]<<"."<<pucIP[2]<<"."<<pucIP[3];
	return stream.str();
}

string string2utf(const wstring& srcString)
{
	const char* src = (const char*)srcString.c_str();
	char* target = (char*)malloc(3*srcString.size()+1);
	char* tmp = target;
	for(unsigned int i=0;i<srcString.size()*2;i+=2)
	{
		tmp[0] = (0xE0|((src[i+1]&0xF0)>>4));
		tmp[1] = (0x80 | ((src[i+1]&0x0F)<<2))+((src[i]&0xC0)>>6);
		tmp[2] = (0x80 | (src[i] & 0x3F));
		tmp+=3;
	}
	target[3*srcString.size()]=0;
	string targetString = target;
	free(target);
	return targetString;
}

string ws2s(const wstring& ws)
{
    string curLocale = setlocale(LC_ALL, NULL); // curLocale = "C";
    setlocale(LC_ALL, "chs"); 
    const wchar_t* _Source = ws.c_str();
    size_t _Dsize = 2 * ws.size() + 1;
    char *_Dest = new char[_Dsize];
    memset(_Dest,0,_Dsize);
    wcstombs(_Dest,_Source,_Dsize);
    string result = _Dest;
    delete []_Dest;
    setlocale(LC_ALL, curLocale.c_str());
    return result;
}

wstring s2ws(const string& s)
{
    setlocale(LC_ALL, "chs"); 
    const char* _Source = s.c_str();
    size_t _Dsize = s.size() + 1;
    wchar_t *_Dest = new wchar_t[_Dsize];
    wmemset(_Dest, 0, _Dsize);
    int nret = mbstowcs(_Dest,_Source,_Dsize);
    wstring result = _Dest;
    delete []_Dest;
    setlocale(LC_ALL, "C");
    return result;
}

wstring UTF2Uni(const char* src, std::wstring &t)
{
    if (src == NULL) 
    {
        return L"";
    }
    
    int size_s = strlen(src);
    int size_d = size_s + 10;          //?
    
    wchar_t *des = new wchar_t[size_d];
    memset(des, 0, size_d * sizeof(wchar_t));
    
    int s = 0, d = 0;
    bool toomuchbyte = true; //set true to skip error prefix.
    
    while (s < size_s && d < size_d)
    {
        unsigned char c = src[s];
        if ((c & 0x80) == 0) 
        {
            des[d++] += src[s++];
        } 
        else if((c & 0xE0) == 0xC0)  ///< 110x-xxxx 10xx-xxxx
        {
            WCHAR &wideChar = des[d++];
            wideChar  = (src[s + 0] & 0x3F) << 6;
            wideChar |= (src[s + 1] & 0x3F);
            
            s += 2;
        }
        else if((c & 0xF0) == 0xE0)  ///< 1110-xxxx 10xx-xxxx 10xx-xxxx
        {
            WCHAR &wideChar = des[d++];
            
            wideChar  = (src[s + 0] & 0x1F) << 12;
            wideChar |= (src[s + 1] & 0x3F) << 6;
            wideChar |= (src[s + 2] & 0x3F);
            
            s += 3;
        } 
        else if((c & 0xF8) == 0xF0)  ///< 1111-0xxx 10xx-xxxx 10xx-xxxx 10xx-xxxx 
        {
            WCHAR &wideChar = des[d++];
            
            wideChar  = (src[s + 0] & 0x0F) << 18;
            wideChar  = (src[s + 1] & 0x3F) << 12;
            wideChar |= (src[s + 2] & 0x3F) << 6;
            wideChar |= (src[s + 3] & 0x3F);
            
            s += 4;
        } 
        else 
        {
            WCHAR &wideChar = des[d++]; ///< 1111-10xx 10xx-xxxx 10xx-xxxx 10xx-xxxx 10xx-xxxx 
            
            wideChar  = (src[s + 0] & 0x07) << 24;
            wideChar  = (src[s + 1] & 0x3F) << 18;
            wideChar  = (src[s + 2] & 0x3F) << 12;
            wideChar |= (src[s + 3] & 0x3F) << 6;
            wideChar |= (src[s + 4] & 0x3F);
            
            s += 5;
        }
    }
    
    t = des;
    delete[] des;
    des = NULL;
    
    return t;
}

int Uni2UTF( const wstring& strRes, char *utf8, int nMaxSize )
{
    if (utf8 == NULL) {
        return -1;
    }
    int len = 0;
    int size_d = nMaxSize;


    for (wstring::const_iterator it = strRes.begin(); it != strRes.end(); ++it)
    {
        wchar_t wchar = *it;
        if (wchar < 0x80)
        {  //
            //length = 1;
            utf8[len++] = (char)wchar;
        }
        else if(wchar < 0x800)
        {
            //length = 2;
            
            if (len + 1 >= size_d)
                return -1;
            
            utf8[len++] = 0xc0 | ( wchar >> 6 );
            utf8[len++] = 0x80 | ( wchar & 0x3f );
        }
        else if(wchar < 0x10000 )
        {
            //length = 3;
            if (len + 2 >= size_d)
                return -1;
            
            utf8[len++] = 0xe0 | ( wchar >> 12 );
            utf8[len++] = 0x80 | ( (wchar >> 6) & 0x3f );
            utf8[len++] = 0x80 | ( wchar & 0x3f );
        }
        else if( wchar < 0x200000 ) 
        {
            //length = 4;
            if (len + 3 >= size_d)
                return -1;
            
            utf8[len++] = 0xf0 | ( (int)wchar >> 18 );
            utf8[len++] = 0x80 | ( (wchar >> 12) & 0x3f );
            utf8[len++] = 0x80 | ( (wchar >> 6) & 0x3f );
            utf8[len++] = 0x80 | ( wchar & 0x3f );
        }
    }
    return len;
}

string s2utfs(const  string&  strSrc)
{
    string  strRes;
    wstring  wstrUni = s2ws(strSrc);
    
    char*  chUTF8 = new char[wstrUni.length() * 3+1];
	memset(chUTF8,0x00,wstrUni.length() * 3+1);
    Uni2UTF(wstrUni,chUTF8, wstrUni.length() * 3);
    strRes = chUTF8;    
    delete  []chUTF8;
    return strRes;
}
string  utfs2s(const string& strutf)
{
    wstring  wStrTmp;
    UTF2Uni( strutf.c_str(),wStrTmp);
    return ws2s(wStrTmp);
}

void replace(string& str,string oldstr,string newstr)
{
	std::string::size_type pos=0;
	std::string::size_type cur_pos=0;
	std::string::size_type old_str_len = oldstr.size();
	std::string::size_type new_str_len = newstr.size();
	while((pos=str.find(oldstr,cur_pos))!=string::npos)
	{
		str.replace(pos,old_str_len,newstr);
		cur_pos = pos +new_str_len;
	}
}

void kad_wait(int seconds)   
{   
	boost::this_thread::sleep(boost::posix_time::seconds(seconds));   
}
void kad_wait_ms(int mseconds)
{
	boost::this_thread::sleep(boost::posix_time::milliseconds(mseconds));   
}
string getCurrentTimeString()
{
	using namespace boost::posix_time;
	ptime now = second_clock::local_time();
    string now_str = to_simple_string(now.date())+"_"+to_simple_string(now.time_of_day());
    replace(now_str,":","_");
	return now_str;
}

bool strIsMD4(const string& message,uchar* hash)
{
	memset(hash,0,16);
	if(message.size() != 16*2)
		return false;
	for(int i=0;i<16;i++)
	{
		char bytes[3];
		bytes[0] = (char)message[i*2+0];
		bytes[1] = (char)message[i*2+1];
		bytes[2] = '\0';

		unsigned int b;
		if(sscanf(bytes,"%x",&b) != 1)
			return false;
		hash[i] = (char)b;
	}
	return true;
}
