#include "config.h"
#include "KadClientCredits.h"

KadClientCredits::KadClientCredits(void)
{
	publicKeyLen=0;
	IdentState = IS_NOTAVAILABLE;
	cryptRndChallengeFrom = 0;
	cryptRndChallengeFor = 0;
}

KadClientCredits::~KadClientCredits(void)
{
}

bool KadClientCredits::SetSecureIdent(const unsigned char* bufIdent,uint8 identLen)
{
	if(MAXPUBKEYSIZE < identLen)
		return false;
	memcpy(publicKey,bufIdent,identLen);
	IdentState = IS_IDNEEDED;
	publicKeyLen = identLen;
	return true;
}

bool KadClientCreditsPool::CreateKeyPair()
{
	try
	{
		CryptoPP::AutoSeededRandomPool rng;
		InvertibleRSAFunction privkey;
		privkey.Initialize(rng,RSAKEYSIZE);

		CryptoPP::Base64Encoder privkeysink(new FileSink("cryptkey.dat"));
		privkey.DEREncode(privkeysink);
		privkeysink.MessageEnd();
	}
	catch (...)
	{
		DEBUG_PRINT1("KadClientCreditsPool£º Error in creating keypair\n");
		return false;
	}
	return true;
}

void KadClientCreditsPool::InitalizeCrypting()
{
	try
	{
		FileSource filesource("cryptkey.dat",true,new Base64Decoder);
	}
	catch (...)
	{
		DEBUG_PRINT1("cryptkey.dat not exist or corrupted\n");
		CreateKeyPair();
	}
	try
	{
		FileSource filesource("cryptkey.dat",true,new Base64Decoder);
		pSignkey = new RSASSA_PKCS1v15_SHA_Signer(filesource);
		RSASSA_PKCS1v15_SHA_Verifier pubkey(*pSignkey);
		ArraySink asink(publicKey,80);
		pubkey.DEREncode(asink);
		publicKey_len = asink.TotalPutLength();
		asink.MessageEnd();
	}
	catch (...)
	{
		DEBUG_PRINT1("Error in creating pubkey\n");
	}
}

UINT KadClientCreditsPool::CreateSignature(KadClientCredits* pClientCredit,unsigned char* pOutput,uint8 max_size,uint32 ChallengeIP,uint8 by_chaIPKind)
{
	SecByteBlock signature(pSignkey->SignatureLength());
	AutoSeededRandomPool rng;
	unsigned char buffer[MAXPUBKEYSIZE+9];
	uint32 keylen = pClientCredit->GetSecIDKeyLen();
	memcpy(buffer,pClientCredit->GetSecureIdent(),keylen);

	uint32 challenge = pClientCredit->cryptRndChallengeFrom;
	PokeUInt32(buffer+keylen,challenge);

	uint16 ChIpLen = 0;
	if(by_chaIPKind)
	{
		ChIpLen = 5;
		PokeUInt32(buffer+keylen+4,ChallengeIP);
		PokeUInt32(buffer+keylen+4+4,by_chaIPKind);
	}

	pSignkey->SignMessage(rng,buffer,keylen+4+ChIpLen,signature.begin());
	ArraySink asink(pOutput,max_size);
	asink.Put(signature.begin(),signature.size());

	uint8 nResult = (uint8)asink.TotalPutLength();
	return nResult;
}

UINT KadClientCreditsPool::VerifyIdent(KadClientCredits* pClientCredit,const unsigned char* pSignature,uint8 in_size,uint32 forIP,uint8 by_chaIPKind)
{
	bool bResult;

	try
	{
		StringSource ss_pubkey(pClientCredit->GetSecureIdent(),pClientCredit->GetSecIDKeyLen(),true,0);
		RSASSA_PKCS1v15_SHA_Verifier pubkey(ss_pubkey);
		unsigned char buffer[MAXPUBKEYSIZE+9];
		memcpy(buffer,publicKey,publicKey_len);
		uint32 challenge = pClientCredit->cryptRndChallengeFor;
		PokeUInt32(buffer+publicKey_len,challenge);

		uint8 chIpSize=0;
		if(by_chaIPKind)
		{
			chIpSize=5;
			uint32 challengIP=0;
			switch(by_chaIPKind)
			{
			case CRYPT_CIP_LOCALCLIENT:
				challengIP = forIP;
				break;
			case CRYPT_CIP_REMOTECLIENT:
				DEBUG_PRINT1("Not Supported\n");
				break;
			case CRYPT_CIP_NONECLIENT:
				challengIP = 0;
				break;
			}
			PokeUInt32(buffer+publicKey_len+4,challengIP);
			PokeUInt32(buffer+publicKey_len+4+4,by_chaIPKind);
		}

		bResult = pubkey.VerifyMessage(buffer,publicKey_len+4+chIpSize,pSignature,in_size);
	}
	catch (...)
	{
		bResult=false;
	}
	
	if(!bResult)
	{
		if(pClientCredit->IdentState == IS_IDNEEDED)
			pClientCredit->IdentState = IS_IDFAILED;
	}
	else
		pClientCredit->IdentState = IS_IDENTIFIED;
	return bResult;
}
