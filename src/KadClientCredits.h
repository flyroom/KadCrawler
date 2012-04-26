#pragma once

#define MAXPUBKEYSIZE 80

#define CRYPT_CIP_REMOTECLIENT	10
#define CRYPT_CIP_LOCALCLIENT	20
#define CRYPT_CIP_NONECLIENT	30

class KadClientCredits
{
public:
	KadClientCredits(void);
	~KadClientCredits(void);
	
	uint8 GetSecIDKeyLen() const { return publicKeyLen;}
	unsigned char* GetSecureIdent()	{ return publicKey;}
	bool SetSecureIdent(const unsigned char* bufIdent,uint8 identLen);

	uint32 cryptRndChallengeFor;
	uint32 cryptRndChallengeFrom;

	unsigned char publicKey[80];
	uint8 publicKeyLen;

	_EIdentState IdentState;
};

class KadClientCreditsPool
{
public:
	bool CreateKeyPair();
	void InitalizeCrypting();
	UINT CreateSignature(KadClientCredits* pClientCredit,unsigned char* pOutput,uint8 max_size,uint32 ChallengeIP,uint8 by_chaIPKind);
	
	UINT VerifyIdent(KadClientCredits* pClientCredit,const unsigned char* pSignature,uint8 in_size,uint32 forIP,uint8 by_chaIPKind);

	unsigned char* GetPublicKey()		{return publicKey;}
	uint8	GetPublicKeyLen()			{return publicKey_len;}

private:
	CryptoPP::RSASSA_PKCS1v15_SHA_Signer* pSignkey;
	unsigned char publicKey[80];
	uint8 publicKey_len;
};
