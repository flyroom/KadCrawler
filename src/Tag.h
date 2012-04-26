class KadTag
{
public:
	byte m_type;
	string m_name;
	KadTag(byte type,string name):m_name(name)
	{
		m_name = name;
		m_type = type;
	}

	virtual ~KadTag(){}
	//virtual KadTag* Copy() = 0;
	bool IsStr() const
	{
		return m_type == TAGTYPE_STRING;
	}
	bool IsNum() const
	{
		return m_type == TAGTYPE_UINT64 || m_type == TAGTYPE_UINT32 || m_type == TAGTYPE_UINT16 || m_type == TAGTYPE_UINT8 || m_type == TAGTYPE_BOOL || m_type == TAGTYPE_FLOAT32 || m_type == 0xFE;
	}
	bool IsInt() const
	{
		return m_type == TAGTYPE_UINT64 || m_type == TAGTYPE_UINT32 || m_type == TAGTYPE_UINT16 || m_type == TAGTYPE_UINT8 || m_type == 0xFE;
	}

	bool IsBsob() const
	{
		return m_type == TAGTYPE_BSOB;
	}

	bool IsHash() const
	{
		return m_type == TAGTYPE_HASH;
	}

	virtual string GetStr() const
	{
		return "Invalid";
	}

	virtual uint64 GetInt() const
	{
		return 0;
	}

	virtual float GetFloat() const
	{
		return 0.0F;
	}
	virtual const BYTE* GetBsob() const
	{
		return NULL;
	}
	virtual bool GetBool() const
	{
		return false;
	}
	virtual const BYTE* GetHash() const
	{
		return NULL;
	}

	virtual uint8 GetBsobSize() const
	{
		return 0;
	}
};

class KadTagStr : public KadTag
{
public:
	KadTagStr(string name,char* value):KadTag(TAGTYPE_STRING,name),m_value(value)
	{}

	virtual string GetStr() const
	{
		return m_value;
	}
protected:
	string m_value;
};

class KadTagUInt : public KadTag
{
public:
	KadTagUInt(string name,uint64 value):KadTag(0xFE,name),m_value(value)
	{}
	virtual uint64 GetInt() const
	{
		return m_value;
	}
protected:
	uint64 m_value;
};

class KadTagUInt64 : public KadTag
{
public:
	KadTagUInt64(string name,uint64 value):KadTag(TAGTYPE_UINT64,name),m_value(value)
	{}
	virtual uint64 GetInt() const
	{
		return m_value;
	}
protected:
	uint64 m_value;
};

class KadTagUInt32 : public KadTag
{
public:
	KadTagUInt32(string name,uint32 value):KadTag(TAGTYPE_UINT32,name),m_value(value)
	{}
	virtual uint64 GetInt() const
	{
		return m_value;
	}
protected:
	uint32 m_value;
};

class KadTagUInt16 : public KadTag
{
public:
	KadTagUInt16(string name,uint16 value):KadTag(TAGTYPE_UINT16,name),m_value(value)
	{}
	virtual uint64 GetInt() const
	{
		return m_value;
	}
protected:
	uint16 m_value;
};

class KadTagUInt8 : public KadTag
{
public:
	KadTagUInt8(string name,uint8 value):KadTag(TAGTYPE_UINT8,name),m_value(value)
	{}
	virtual uint64 GetInt() const
	{
		return m_value;
	}
protected:
	uint8 m_value;
};

class KadTagFloat : public KadTag
{
public:
	KadTagFloat(string name,float value):KadTag(TAGTYPE_FLOAT32,name),m_value(value)
	{}
	virtual float GetFloat() const
	{
		return m_value;
	}
protected:
	float m_value;
};

class KadTagBool : public KadTag
{
public:
	KadTagBool(string name,bool value):KadTag(TAGTYPE_BOOL,name),m_value(value)
	{}
	virtual bool GetBool() const
	{
		return m_value;
	}
protected:
	bool m_value;
};


class KadTagHash : public KadTag
{
public:
	KadTagHash(string name,const byte* value):KadTag(TAGTYPE_HASH,name)
	{
		m_value = new BYTE[16];
		md4cpy(m_value,value);
	}
	~KadTagHash()
	{
		delete[] m_value;
	}
	virtual const BYTE* GetHash() const
	{
		return m_value;
	}
protected:
	BYTE* m_value;
};

class KadTagBsob : public KadTag
{
public:
	KadTagBsob(string name,const byte* value,uint8 nSize):KadTag(TAGTYPE_BSOB,name)
	{
		m_value = new BYTE[nSize];
		memcpy(m_value,value,nSize);
	}
	~KadTagBsob()
	{
		delete[] m_value;
	}
	virtual const BYTE* GetBsob() const
	{
		return m_value;
	}
	virtual uint8 GetBsobSize() const
	{
		return m_size;
	}
protected:
	BYTE* m_value;
	uint8 m_size;
};

typedef std::list<KadTag*> TagList;
