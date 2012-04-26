typedef unsigned char uint8;
typedef unsigned char uchar;
typedef unsigned short uint16;
typedef unsigned long uint32;
#ifdef WIN32
typedef unsigned __int64 uint64;
#else
typedef long long uint64;
#endif
typedef unsigned char BYTE;
typedef unsigned long ULONG;
typedef unsigned int UINT;

struct RC4_Key_Struct{
	uint8 abyState[256];
	uint8 byX;
	uint8 byY;
};

RC4_Key_Struct* RC4CreateKey(const uchar* pachKeyData,uint32 nLen,RC4_Key_Struct* key=NULL,bool bSkipDiscard=false);
void RC4Crypt(const uchar* pachIn,uchar* pachOut,uint32 nLen,RC4_Key_Struct* key);


__inline int md4cmp(const void* hash1, const void* hash2) {
	return !(((uint64*)hash1)[0] == ((uint64*)hash2)[0] &&
		((uint64*)hash1)[1] == ((uint64*)hash2)[1]);
}

__inline bool isnulmd4(const void* hash) {
	return  (((uint64*)hash)[0] == 0 &&
		((uint64*)hash)[1] == 0);
}

// md4clr -- replacement for memset(hash,0,16)
__inline void md4clr(const void* hash) {
	((uint64*)hash)[0] = 0;
	((uint64*)hash)[1] = 0;
}

// md4cpy -- replacement for MEMCOPY(dst,src,16)
__inline void md4cpy(void* dst, const void* src) {
	((uint64*)dst)[0] = ((uint64*)src)[0];
	((uint64*)dst)[1] = ((uint64*)src)[1];
}

__inline void PokeUInt8(void* p, uint8 nVal)
{
	*((uint8*)p) = nVal;
}

__inline void PokeUInt16(void* p, uint16 nVal)
{
	*((uint16*)p) = nVal;
}

__inline void PokeUInt32(void* p, uint32 nVal)
{
	*((uint32*)p) = nVal;
}

__inline void PokeUInt64(void* p, uint64 nVal)
{
	*((uint64*)p) = nVal;
}

__inline uint8 PeekUInt8(const void* p)
{
	return *((uint8*)p);
}

__inline uint16 PeekUInt16(const void* p)
{
	return *((uint16*)p);
}

__inline uint32 PeekUInt32(const void* p)
{
	return *((uint32*)p);
}

__inline uint64 PeekUInt64(const void* p)
{
	return *((uint64*)p);
}

string ipstr(uint32 nIP);

bool strIsMD4(const string& message,uchar* hash);

#define CRYPT_HEADER_WITHOUTPADDING 8
#define MAGICVALUE_UDP				91
#define MAGICVALUE_UDP_SYNC_CLIENT	0x395F2EC1
#define MAGICVALUE_UDP_SYNC_SERVER  0x13EF24D5
#define MAGICVALUE_UDP_SERVERCLIENT 0xA5
#define MAGICVALUE_UDP_CLIENTSERVER 0x6B

template <typename T>
struct LockFreeQueue
{
	LockFreeQueue()
	{
		list.push_back(T());
		iHead = list.begin();
		iTail = list.end();
	}
	void Produce(const T& t)
	{
		list.push_back(t);
		iTail= list.end();
		list.erase(list.begin(),iHead);
	}
	bool Consume(T& t)
	{
		typename TList::iterator iNext = iHead;
		++iNext;
		if(iNext != iTail)
		{
			iHead = iNext;
			t = *iHead;
			return true;
		}
		return false;
	}
private:
	typedef std::list<T> TList;
	TList list;
	typename TList::iterator iHead,iTail;
};

template <typename T>
struct WaitFreeQueue
{
	void Produce(const T& t)
	{
		queue.Produce(t);
		cond.notify_one();
	}
	bool Consume(T& t)
	{
		return queue.Consume(t);
	}

	T Consume(int wait_time = 1/* milliseconds */)
	{
		T tmp;
		if(Consume(tmp))
			return tmp;
		boost::mutex::scoped_lock lock(mtx);
		while(!Consume(tmp))
		{
			boost::xtime t;
			boost::xtime_get(&t,boost::TIME_UTC);
			//AddMilliseconds(t,wait_time);
			cond.timed_wait(lock,t);
		}
		return tmp;
	}
private:
	LockFreeQueue<T> queue;
	boost::condition cond;
	boost::mutex mtx;
};

string string2utf(const wstring& srcString);
wstring UTF2Uni(const char* src, std::wstring &t);
int Uni2UTF( const wstring& strRes, char *utf8, int nMaxSize);
string ws2s(const wstring& ws);
wstring s2ws(const string& s);
string s2utfs(const  string&  strSrc);
string  utfs2s(const string& strutf);

void replace(string& str,string oldstr,string newstr);

class reset_event
{
	bool flag,auto_reset;
	boost::condition_variable cond_var;
	boost::mutex mx_flag;
public:
	explicit reset_event(bool _auto_reset=false):flag(false),auto_reset(_auto_reset){}

	void wait()
	{
		boost::unique_lock<boost::mutex> LOCK(mx_flag);
		if(flag)
		{
			if(flag)
			{
				if(auto_reset)
					flag = false;
				return;
			}
		}
		do 
		{
			cond_var.wait(LOCK);
		} while (!flag);

		if(auto_reset)
			flag = false;
	}

	bool wait(const boost::posix_time::time_duration& dur)
	{
		boost::unique_lock<boost::mutex> LOCK(mx_flag);
		if(flag)
		{
			if(auto_reset)
				flag=false;
			return true;
		}
		bool ret = cond_var.timed_wait(LOCK,dur);
		if(ret && flag)
		{
			if(auto_reset)
				flag=false;
			return true;
		}
		return false;
	}

	void set()
	{
		boost::lock_guard<boost::mutex> LOCK(mx_flag);
		flag = true;
		cond_var.notify_one();
	}

	void reset()
	{
		boost::lock_guard<boost::mutex> LOCK(mx_flag);
		flag = false;
	}
};

void kad_wait(int seconds);
void kad_wait_ms(int mseconds);
string getCurrentTimeString();
