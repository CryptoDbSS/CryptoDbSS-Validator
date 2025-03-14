/*******************************************************************************

 * This notice, including the copyright notice and permission notice, 
 * must be retained in all copies or substantial portions of the Software and 
 * in all derivative works.
 *
 * Software Name: CryptoDbSS-Validator
 * Copyright (C) 2025 Steeven J Salazar.
 * License: CryptoDbSS: Software Review and Audit License
 * 
 * https://github.com/CryptoDbSS/CryptoDbSS-Validator
 *
 * IMPORTANT: Before using, compiling, or doing anything with this software,
 * you must read and accept the terms of the License provided with this software.
 *
 * If you do not have a copy of the License, you can obtain it at the following link:
 * https://github.com/CryptoDbSS/CryptoDbSS-Validator/blob/main/LICENSE.md
 *
 * By using, compiling, or modifying this software, you implicitly accept
 * the terms of the License. If you do not agree with the terms,
 * do not use, compile, or modify this software.
 * 
 * This software is provided "as is," without warranty of any kind.
 * For more details, see the LICENSE file.

********************************************************************************/


/* ********************************************************************************
 
    The CryptoDbSS, blockchain-core, consensus, protocols and misc.

    This software is a review and audit release, it should only be used for 
    development, testing, education and auditing purposes. 

    Third-party dependencies: CrowCpp, Crypto++, OpenSSL, Boost, ASIO, libcurl.

    questions, suggestions or contact : Steevenjavier@gmail.com

                                S.S

*********************************************************************************/

#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

#include <sstream>

using namespace CryptoPP;

CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey loadPublicKey2(const unsigned char* pt, size_t size){
    
    HexDecoder decoder;
    decoder.Put(pt, size);
    decoder.MessageEnd();
    CryptoPP::ECP::Point q;
    size_t len = decoder.MaxRetrievable();
    q.identity = false;
    q.x.Decode(decoder, len / 2);
    q.y.Decode(decoder, len / 2);
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
    publicKey.Initialize(CryptoPP::ASN1::secp256k1(), q);

    return publicKey;
}

ECDSA<ECP, CryptoPP::SHA256>::PublicKey loadPublicKey(const std::string &pt)
{
     
    HexDecoder decoder;
    decoder.Put((CryptoPP::byte *)&pt[0], pt.size());
    decoder.MessageEnd();
    ECP::Point q;
    size_t len = decoder.MaxRetrievable();
    q.identity = false;
    q.x.Decode(decoder, len / 2);
    q.y.Decode(decoder, len / 2);
    CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::PublicKey publicKey;
    publicKey.Initialize(ASN1::secp256k1(), q);

    //    Integer x = publicKey.GetPublicElement().x;
    //    Integer y = publicKey.GetPublicElement().y;
    //    std::string xStr, yStr;
    //    x.Encode(HexEncoder(new StringSink(xStr)).Ref(), x.MinEncodedSize());
    //    y.Encode(HexEncoder(new StringSink(yStr)).Ref(), y.MinEncodedSize());

    // Imprimir las coordenadas x e y en hexadecimal
    // std::cout << "Coordenada x: " << xStr << std::endl;
    // std::cout << "Coordenada y: " << yStr << std::endl;

    return publicKey;
}

bool verifySignatureCryptoPP(unsigned char (&Transaction)[], uint8_t transactionSize, unsigned char (&signature)[64] , array<unsigned char,64>publickey){

    string message="";
    string accStg =""; 
    string signature_hex =""; 
    for(uint8_t i = 0 ; i<64; i++){
        
        accStg+= byteToHex2(publickey[i]);

    }
    for(uint8_t i = 0 ; i<transactionSize; i++){
        message+= byteToHex2(Transaction[i]);
    }
    for(uint8_t i = 0 ; i<64; i++){
        signature_hex+= byteToHex2(signature[i]);
    }

    CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::PublicKey publicKey= loadPublicKey(accStg);

    try {
        std::string signature_str;
        StringSource(signature_hex, true, new HexDecoder(new StringSink(signature_str)));
        const CryptoPP::byte *signature = reinterpret_cast<const CryptoPP::byte *>(signature_str.data());
        size_t signature_size = signature_str.size();
        // Verificación de la firma digital
        CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::Verifier verifier(publicKey);
        bool result = verifier.VerifyMessage((const CryptoPP::byte *)&message[0], message.size(), signature, signature_size);

    if (!result){
        return false;
    }
    return result;

    } catch (const std::exception& e) {
        return false;
    }

}

std::string derivate(std::string priv){

    HexDecoder decoder;
    decoder.Put((CryptoPP::byte *)&priv[0], priv.size());
    decoder.MessageEnd();
    Integer x;

    x.Decode(decoder, decoder.MaxRetrievable());

    CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::PrivateKey k2;
 
 
    k2.Initialize(ASN1::secp256k1(), x);
    CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::PublicKey publicKey;
    k2.MakePublicKey(publicKey);
    std::ostringstream oss;

    HexEncoder encoder2(new FileSink(oss));
    publicKey.DEREncodePublicKey(encoder2);
    std::string output = oss.str();
    
    memset(&publicKey, 0, sizeof(publicKey));
    memset(&k2, 0, sizeof(k2));
    memset(&x, 0, sizeof(x));
    memset(&decoder, 0, sizeof(decoder));
    memset(&priv, 0, sizeof(priv));
    return output;
    
}

bool verifySignature(const std::string &message, const std::string &signature_hex, const CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::PublicKey &publicKey){

    try {
        std::string signature_str;
        StringSource(signature_hex, true, new HexDecoder(new StringSink(signature_str)));
        const CryptoPP::byte *signature = reinterpret_cast<const CryptoPP::byte *>(signature_str.data());
        size_t signature_size = signature_str.size();
        // Verificación de la firma digital
        CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::Verifier verifier(publicKey);

        bool result = verifier.VerifyMessage((const CryptoPP::byte *)&message[0], message.size(), signature, signature_size);

    if (!result){
        return false;
    }
    return result;

    } catch (const std::exception& e) {
        return false;
    }

}

std::string Signer(std::string priv, std::string message) {

    HexDecoder decoder;
    decoder.Put((CryptoPP::byte*)&priv[0], priv.size());
    decoder.MessageEnd();

    Integer x;
    x.Decode(decoder, decoder.MaxRetrievable());

    CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::PrivateKey k2;
    k2.Initialize(ASN1::secp256k1(), x);

    CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::PublicKey publicKey;
    k2.MakePublicKey(publicKey);

    x = publicKey.GetPublicElement().x;
    Integer y = publicKey.GetPublicElement().y;
    std::string xStr, yStr;
    x.Encode(HexEncoder(new StringSink(xStr)).Ref(), x.MinEncodedSize());
    y.Encode(HexEncoder(new StringSink(yStr)).Ref(), y.MinEncodedSize());

    // Use std::unique_ptr to manage the lifetime of the Signer object
    std::unique_ptr<CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::Signer> signer(new CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::Signer(k2));

    size_t siglen = signer->MaxSignatureLength();
    std::string signature(siglen, 0x00);

    AutoSeededRandomPool prng;
    siglen = signer->SignMessage(prng, (const CryptoPP::byte*)&message[0], message.size(), (CryptoPP::byte*)&signature[0]);
    signature.resize(siglen);

    std::string signature_hex;
    StringSource((const CryptoPP::byte*)&signature[0], signature.size(), true, new HexEncoder(new StringSink(signature_hex)));

    bool lastok = verifySignature(message, signature_hex, publicKey);

    if (!lastok) {
        std::cout << "FAIL :(" << std::endl;
        return "signing error";
    } else {
        return signature_hex;
    }
}

bool verifySignature2(const unsigned char message[], size_t messageLen, const unsigned char signature_hex[], size_t signature_hexLen, const CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::PublicKey& publicKey) {
    try {
        std::string signature_str;
        StringSource(signature_hex, signature_hexLen, true, new HexDecoder(new StringSink(signature_str)));
        const CryptoPP::byte* signature = reinterpret_cast<const CryptoPP::byte*>(signature_str.data());
        size_t signature_size = signature_str.size();

        // Verificación de la firma digital
        CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::Verifier verifier(publicKey);
        bool result = verifier.VerifyMessage(message, messageLen, signature, signature_size);

        return result;
    } catch (const std::exception& e) {
        return false;
    }
}

//SUCCESS
unsigned char* derivate2( std::string& priv){
    HexDecoder decoder;
    decoder.Put((CryptoPP::byte *)&priv[0], priv.size());
    decoder.MessageEnd();
    Integer x;

    x.Decode(decoder, decoder.MaxRetrievable());

    CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::PrivateKey k2;
    k2.Initialize(ASN1::secp256k1(), x);
    CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::PublicKey publicKey;
    k2.MakePublicKey(publicKey);

    size_t publicKeySize = 65;
    unsigned char* output = new unsigned char[publicKeySize];
    CryptoPP::ArraySink sink(output, publicKeySize);
    publicKey.DEREncodePublicKey(sink);

    memset(&publicKey, 0, sizeof(publicKey));
    memset(&k2, 0, sizeof(k2));
    memset(&x, 0, sizeof(x));
    memset(&decoder, 0, sizeof(decoder));
    return output;
}
std::string Signer2(std::string priv, std::string message){

    HexDecoder decoder;
    decoder.Put((CryptoPP::byte *)&priv[0], priv.size());
    decoder.MessageEnd();

    Integer x;

    x.Decode(decoder, decoder.MaxRetrievable());

    CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::PrivateKey k2;
    k2.Initialize(ASN1::secp256k1(), x);
    CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::PublicKey publicKey;
    k2.MakePublicKey(publicKey);

    x = publicKey.GetPublicElement().x;
    Integer y = publicKey.GetPublicElement().y;
    std::string xStr, yStr;
    x.Encode(HexEncoder(new StringSink(xStr)).Ref(), x.MinEncodedSize());
    y.Encode(HexEncoder(new StringSink(yStr)).Ref(), y.MinEncodedSize());
    /*
    // Imprimir las coordenadas x e y en hexadecimal
    std::cout << "Coordenada x: " << xStr << std::endl;
    std::cout << "Coordenada y: " << yStr << std::endl;
    */
    CryptoPP::ECDSA<ECP, CryptoPP::SHA256>::Signer signer(k2);

    size_t siglen = signer.MaxSignatureLength();
    std::string signature(siglen, 0x00);

    AutoSeededRandomPool prng;
    siglen = signer.SignMessage(prng, (const CryptoPP::byte *)&message[0], message.size(), (CryptoPP::byte *)&signature[0]);
    signature.resize(siglen);

    std::string signature_hex;

    std::cout<<signature_hex;
    StringSource((const CryptoPP::byte *)&signature[0], signature.size(), true, new HexEncoder(new StringSink(signature_hex)));

    bool lastok = verifySignature(message, signature_hex, publicKey);

    if (!lastok)
    {
        std::cout << "FAIL :(" << std::endl;
    }
    else
    {
        /*
        std::cout << "OK :)" << std::endl;

        std::cout << "la firma es " + signature_hex << std::endl;
        */
        memset(&prng, 0, sizeof(prng));
        memset(&signer, 0, sizeof(signer));
        memset(&publicKey, 0, sizeof(publicKey));
        memset(&k2, 0, sizeof(k2));
        memset(&x, 0, sizeof(x));
        memset(&decoder, 0, sizeof(decoder));
        memset(&priv, 0, sizeof(priv));
        
        return signature_hex;
    }

    return "signing error";
}