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

#ifndef COMPRESION_H
#define COMPRESION_H

#include "CryptoDbSS.cpp"
#include "TransactionType.h"


using namespace std;

bool PrimerChange(uint8_t bltype, uint &primer);
uint8_t AccIndexCompare2(vector<unsigned char>&bl2,uint &primer, array<unsigned char, 64 > &acc);
array<unsigned char, 64 > accArr(string acctpubk);
string readaccountString(string stg, bool side);
string readbalanceString(string stg, bool side);
bool build_blks(uint &qttblks, uint64_t &last, vector<unsigned char> &bl2 );
void exit_call();
string typebl(string bl);
uint8_t TypeTransaction(string &stg);
uint64_t readValueTransactionUint64(string &stg);
string readValueTransactionString(string &stg);

extern uint16_t maxCompPoint;

uint8_t getBlCompressType(uint8_t bltype){ 
    
    if(bltype==0x0B||bltype==0x1A||bltype==0x29||bltype==0x38){
        return 0x0B;
    }
    if(bltype==0x0C||bltype==0x1B||bltype==0x2A||bltype==0x39){
        return 0x0C;
    }
    if(bltype==0x0D||bltype==0x1C||bltype==0x2B||bltype==0x3A){
        return 0x0D;
    }
    if(bltype==0x0E||bltype==0x1D||bltype==0x2C||bltype==0x3B){
        return 0x0E;
    }
    if(bltype==0x0F||bltype==0x1E||bltype==0x2D||bltype==0x3C){
        return 0x0F;
    }
    if(bltype==0x10||bltype==0x1F||bltype==0x2E||bltype==0x3D){
        return 0x10;
    }
    if(bltype==0x11||bltype==0x20||bltype==0x2F||bltype==0x3E){
        return 0x11;
    }
    if(bltype==0x12||bltype==0x21||bltype==0x30||bltype==0x3F){
        return 0x12;
    }
    if(bltype==0x13||bltype==0x22||bltype==0x31||bltype==0x40){
        return 0x13;
    }
    if(bltype==0x14||bltype==0x23||bltype==0x32||bltype==0x41){
        return 0x14;
    }
    if(bltype==0x15||bltype==0x24||bltype==0x33||bltype==0x42){
        return 0x15;
    }
    if(bltype==0x16||bltype==0x25||bltype==0x34||bltype==0x43){
        return 0x16;
    }
    if(bltype==0x17||bltype==0x26||bltype==0x35||bltype==0x44){
        return 0x17;
    }
    if(bltype==0x18||bltype==0x27||bltype==0x36||bltype==0x45){
        return 0x18;
    }
    if(bltype==0x19||bltype==0x28||bltype==0x37||bltype==0x46){
        return 0x19;
    }
    return bltype;
}

uint8_t getBlType(uint8_t bltype){

    if ( bltype == 0x00 ||bltype == 0x0B||bltype == 0x0C||bltype == 0x0D||bltype == 0x0E||bltype == 0x0F||bltype == 0x10
        ||bltype == 0x11||bltype == 0x12||bltype == 0x13||bltype == 0x14||bltype == 0x15||bltype == 0x16||bltype == 0x17
        ||bltype == 0x18||bltype == 0x19){

        return 0x00;
    }

    if ( bltype == 0x04 ||bltype == 0x1A||bltype == 0x1B||bltype == 0x1C||bltype == 0x1D||bltype == 0x1E||bltype == 0x1F
        ||bltype == 0x20||bltype == 0x21||bltype == 0x22||bltype == 0x23||bltype == 0x24||bltype == 0x25||bltype == 0x26
        ||bltype == 0x27||bltype == 0x28){

        return 0x04;
    }

    if ( bltype == 0x06 ||bltype == 0x29||bltype == 0x2A||bltype == 0x2B||bltype == 0x2C||bltype == 0x2D||bltype == 0x2E
        ||bltype == 0x2F||bltype == 0x30||bltype == 0x31||bltype == 0x32||bltype == 0x33||bltype == 0x34||bltype == 0x35
        ||bltype == 0x36||bltype == 0x37){

        return 0x06;
    }

    if ( bltype == 0x08 ||bltype == 0x38||bltype == 0x39||bltype == 0x3A||bltype == 0x3B||bltype == 0x3C||bltype == 0x3E
        ||bltype == 0x3F||bltype == 0x40||bltype == 0x41||bltype == 0x42||bltype == 0x43||bltype == 0x44||bltype == 0x45
        ||bltype == 0x46||bltype == 0x47){

        return 0x08;
    }

    return 0xFF;

}

string definebltype(bool (&TransacElementCompression)[4],string &blktype){

    if(!TransacElementCompression[0]&&!TransacElementCompression[1]&&!TransacElementCompression[2]&&!TransacElementCompression[3]){
        if( blktype == "00" || blktype == "04"|| blktype == "06"|| blktype == "08"){ return blktype;}
    }
    if( TransacElementCompression[0]&&!TransacElementCompression[1]&&!TransacElementCompression[2]&&!TransacElementCompression[3]){
        if(blktype== "00"){return "0B";}
        if(blktype== "04"){return "1A";}
        if(blktype== "06"){return "29";}
        if(blktype== "08"){return "38";}
    }
    if(!TransacElementCompression[0]&&!TransacElementCompression[1]&& TransacElementCompression[2]&&!TransacElementCompression[3]){
        if(blktype== "00"){return "0C";}
        if(blktype== "04"){return "1B";}
        if(blktype== "06"){return "2A";}
        if(blktype== "08"){return "39";}
    }
    if(!TransacElementCompression[0]&& TransacElementCompression[1]&&!TransacElementCompression[2]&&!TransacElementCompression[3]){
        if(blktype== "00"){return "0D";}
        if(blktype== "04"){return "1C";}
        if(blktype== "06"){return "2B";}
        if(blktype== "08"){return "3A";}
    }
    if(!TransacElementCompression[0]&&!TransacElementCompression[1]&&!TransacElementCompression[2]&& TransacElementCompression[3]){
        if(blktype== "00"){return "0E";}
        if(blktype== "06"){return "2C";}
        if(blktype== "08"){return "3B";}
    }
    if(!TransacElementCompression[0]&& TransacElementCompression[1]&&!TransacElementCompression[2]&& TransacElementCompression[3]){
        if(blktype== "00"){return "0F";}
        if(blktype== "06"){return "2D";}
        if(blktype== "08"){return "3C";}
    }
    if( TransacElementCompression[0]&& TransacElementCompression[1]&&!TransacElementCompression[2]&&!TransacElementCompression[3]){
        if(blktype== "00"){return "10";}
        if(blktype== "04"){return "1F";}
        if(blktype== "06"){return "2E";}
        if(blktype== "08"){return "3D";}
    }
    if( TransacElementCompression[0]&&!TransacElementCompression[1]&&!TransacElementCompression[2]&& TransacElementCompression[3]){
        if(blktype== "00"){return "11";}
        if(blktype== "06"){return "2F";}
        if(blktype== "08"){return "3E";}
    }
    if( TransacElementCompression[0]&& TransacElementCompression[1]&&!TransacElementCompression[2]&& TransacElementCompression[3]){
        if(blktype== "00"){return "12";}
        if(blktype== "06"){return "30";}
        if(blktype== "08"){return "3F";}
    }
    if(!TransacElementCompression[0]&& TransacElementCompression[1]&& TransacElementCompression[2]&&!TransacElementCompression[3]){
        if(blktype== "00"){return "13";}
        if(blktype== "04"){return "22";}
        if(blktype== "06"){return "31";}
        if(blktype== "08"){return "40";}
    }
    if(!TransacElementCompression[0]&&!TransacElementCompression[1]&& TransacElementCompression[2]&& TransacElementCompression[3]){
        if(blktype== "00"){return "14";}
        if(blktype== "06"){return "32";}
        if(blktype== "08"){return "41";}
    }
    if(!TransacElementCompression[0]&& TransacElementCompression[1]&& TransacElementCompression[2]&& TransacElementCompression[3]){
        if(blktype== "00"){return "15";}
        if(blktype== "06"){return "33";}
        if(blktype== "08"){return "42";}
    }
    if( TransacElementCompression[0]&&!TransacElementCompression[1]&& TransacElementCompression[2]&&!TransacElementCompression[3]){
        if(blktype== "00"){return "16";}
        if(blktype== "04"){return "25";}
        if(blktype== "06"){return "34";}
        if(blktype== "08"){return "43";}
    }
    if( TransacElementCompression[0]&& TransacElementCompression[1]&& TransacElementCompression[2]&&!TransacElementCompression[3]){
        if(blktype== "00"){return "17";}
        if(blktype== "04"){return "26";}
        if(blktype== "06"){return "35";}
        if(blktype== "08"){return "44";}
    }
    if( TransacElementCompression[0]&&!TransacElementCompression[1]&& TransacElementCompression[2]&& TransacElementCompression[3]){
        if(blktype== "00"){return "18";}
        if(blktype== "06"){return "36";}
        if(blktype== "08"){return "45";}
    }
    if( TransacElementCompression[0]&& TransacElementCompression[1]&& TransacElementCompression[2]&& TransacElementCompression[3]){
        if(blktype== "00"){return "19";}
        if(blktype== "06"){return "37";}
        if(blktype== "08"){return "46";}
    }

    cout<<endl<<"definebltype() blktype no match"<<endl;

    exit_call();

    return "FF";
    
}

uint8_t definebltype0x0A(bool (&TransacElementCompression)[3],uint8_t &blktype){

    if(!TransacElementCompression[0]&&!TransacElementCompression[1]&&!TransacElementCompression[2]){
        switch(blktype){
            case 0x0A:
                return 0x1D;
            case 0x0C:
                return 0x47;
            default:

                cout<<endl<<"definebltype0x0A blktype no match - 0A 0C"<<endl;
                exit_call();
        }
    }
    if( !TransacElementCompression[0]&&!TransacElementCompression[1]&&TransacElementCompression[2]){
        if(blktype== 0x0A){return 0x1E;}
    }
    if( !TransacElementCompression[0]&&TransacElementCompression[1]&&!TransacElementCompression[2]){
        if(blktype== 0x0A){return 0x20;}
        if(blktype== 0x0C){return 0x48;}
    }
    if( !TransacElementCompression[0]&&TransacElementCompression[1]&&TransacElementCompression[2]){
        if(blktype== 0x0A){return 0x21;}
    }
    if( TransacElementCompression[0]&&!TransacElementCompression[1]&&!TransacElementCompression[2]){
        if(blktype== 0x0A){return 0x23;}
        if(blktype== 0x0C){return 0x49;}
    }
    if( TransacElementCompression[0]&&!TransacElementCompression[1]&&TransacElementCompression[2]){
        if(blktype== 0x0A){return 0x24;}
        
    }
    if( TransacElementCompression[0]&&TransacElementCompression[1]&&!TransacElementCompression[2]){
        if(blktype== 0x0A){return 0x27;}
        if(blktype== 0x0C){return 0x4A;}
    }
    if( TransacElementCompression[0]&&TransacElementCompression[1]&&TransacElementCompression[2]){
        if(blktype== 0x0A){return 0x28;}
    }

    cout<<endl<<"definebltype0x0A blktype no match"<<endl;
    exit_call();

    return 0xFF;
    
}

string compressAccStr(string AccUncompressed){
    return AccUncompressed.substr(124,4);
}

string compress0x0A(string &DataTransactionUncompressed, uint16_t lastTopTransac){

    extern string* blksOP;
    extern map< array <unsigned char,64>, Accsync >AccSync;

    bool TransacElementCompression [3];
    uint8_t blktype= TypeTransaction(DataTransactionUncompressed);
    string newCompressedtransac="";
    string accL = readaccountString(DataTransactionUncompressed, false);
    array<unsigned char, 64 > acc = accArr( accL );
    
    newCompressedtransac+=DataTransactionUncompressed.substr(TransactionDataFormat[blktype].POS_transactionNumber_string, TransactionDataFormat[blktype].size_transactionNumber_string );

    //cout<<endl<<" compressor debug 0x0a newCompressedtransac "<<newCompressedtransac<<endl;

    // 1 accL compress
    auto it  = AccSync.find(acc);
    if (it != AccSync.end()){
        //cout<<endl<<"debug compress0x0A accL AccSync[acc].DataCompressIndex "<<AccSync[acc].DataCompressIndex<<endl;
        if(  AccSync[acc].DataCompressIndex!=0 &&  AccSync[acc].DataCompressIndex <= maxCompPoint ) {
            newCompressedtransac += uint16ToHex(AccSync[acc].DataCompressIndex)+compressAccStr(accL);
            TransacElementCompression[0]=true;
        } else { 

            for(uint16_t i = 0; i <= lastTopTransac; i++){

                uint8_t bltypetransaction = hexToUint8_t(typebl(blksOP[i]));

                if(bltypetransaction == 0x00 || bltypetransaction == 0x04 || bltypetransaction == 0x06|| bltypetransaction == 0x08){

                    if (i == lastTopTransac){ 
                        newCompressedtransac += accL;
                        TransacElementCompression[0]=false;
                        AccSync[acc].DataCompressIndex=0;
                        break;
                    }
                    if(readaccountString(blksOP[i], false) == accL) {
                        newCompressedtransac += uint16ToHex(0)+compressAccStr(accL);
                        TransacElementCompression[0]=true;
                        break;
                    }
                    if(readaccountString(blksOP[i], true) == accL) {
                        newCompressedtransac += uint16ToHex(0)+compressAccStr(accL);
                        TransacElementCompression[0]=true;
                        break;
                    }
                }

                if(bltypetransaction == 0x0A || bltypetransaction == 0x0C){

                    if (i == lastTopTransac){ 
                        newCompressedtransac += accL;
                        TransacElementCompression[0]=false;
                        AccSync[acc].DataCompressIndex=0;
                        break;
                    }
                    if(readaccountString(blksOP[i], false) == accL) {
                        newCompressedtransac += uint16ToHex(0)+compressAccStr(accL);
                        TransacElementCompression[0]=true;
                        break;
                    }

                }

            }
        }
    } else { 
        cout<<endl<<"handle the several internal memory error compress0x0A it != AccSync.end() ";
        exit_call();
        //handle the several internal memory error
    }

    // 2 valueL Compress
    if ( hexToUint64( readbalanceString(DataTransactionUncompressed , false)) <=4294967295 ){
        //cout<<endl<<"debug transac compresed valuel "<<hexToUint64( readbalanceString(DataTransactionUncompressed , false));
        TransacElementCompression[1]=true;
        newCompressedtransac+=readbalanceString(DataTransactionUncompressed , false).substr(8,8);
    } else {

        TransacElementCompression[1]=false;
        newCompressedtransac+=readbalanceString(DataTransactionUncompressed , false);

    }

    // 3 value transaction Compress
    if(blktype == 0x0A){ 
        if ( readValueTransactionUint64(DataTransactionUncompressed ) <=4294967295 ){
            //out<<endl<<"debug transac compresed valuel "<< readValueTransactionUint64(DataTransactionUncompressed);
            TransacElementCompression[2]=true;
            newCompressedtransac+=readValueTransactionString(DataTransactionUncompressed ).substr(8,8);
        } else {

            TransacElementCompression[2]=false;
            newCompressedtransac+=readValueTransactionString(DataTransactionUncompressed );

        }
    }

    string definedtransac = uint8ToHexPatch(definebltype0x0A(TransacElementCompression,blktype))+newCompressedtransac+DataTransactionUncompressed.substr(TransactionDataFormat[blktype].POS_Msg32bytes_string,TransactionDataFormat[blktype].size_TransactionWithsignWoHidden_string-TransactionDataFormat[blktype].POS_Msg32bytes_string);

    //cout<<endl<<"transac compresed is "<<definedtransac<< endl << endl;
    //cout<<endl<<"transac uncompresed is "<<DataTransactionUncompressed<< endl << endl;

    return definedtransac;

}

string compress0x00(string &DataTransactionUncompressed, uint16_t lastTopTransac){

    extern string* blksOP;
    extern map< array <unsigned char,64>, Accsync >AccSync;

    bool TransacElementCompression [4];
    string blktype= DataTransactionUncompressed.substr(0,2);
    string newCompressedtransac="";
    string accL = readaccountString(DataTransactionUncompressed, false);
    string accR = readaccountString(DataTransactionUncompressed, true);
    array<unsigned char, 64 > acc = accArr( accL );

    // 1 accL compress
    auto it  = AccSync.find(acc);
    if (it != AccSync.end()){
        //cout<<endl<<"debug compressor accL AccSync[acc].DataCompressIndex "<<AccSync[acc].DataCompressIndex<<endl;
        if(  AccSync[acc].DataCompressIndex!=0 &&  AccSync[acc].DataCompressIndex <= maxCompPoint ) {
            newCompressedtransac = uint16ToHex(AccSync[acc].DataCompressIndex)+compressAccStr(accL);
            TransacElementCompression[0]=true;
        } else { 

            for(uint16_t i = 0; i <= lastTopTransac; i++){

                if(typebl(blksOP[i]) == "00" || typebl(blksOP[i]) == "04" || typebl(blksOP[i]) == "06"|| typebl(blksOP[i]) == "08"){

                    if (i == lastTopTransac){
                        newCompressedtransac = accL;
                        TransacElementCompression[0]=false;
                        AccSync[acc].DataCompressIndex=0;
                        break;
                    }
                    if(readaccountString(blksOP[i], false) == accL) {
                        newCompressedtransac = uint16ToHex(0)+compressAccStr(accL);
                        TransacElementCompression[0]=true;
                        break;
                    }
                    if(readaccountString(blksOP[i], true)==accL) {
                        newCompressedtransac = uint16ToHex(0)+compressAccStr(accL);
                        TransacElementCompression[0]=true;
                        break;
                    }
                }
            }
        }
    } else { 
        cout<<endl<<"handle the several internal memory error";
        //handle the several internal memory error
    }

    //cout<<endl<<"transac compresed accl "<<newCompressedtransac;
 
    // 2 valueL Compress
    if ( hexToUint64( readbalanceString(DataTransactionUncompressed , false)) <=4294967295 ){
        //cout<<endl<<"debug transac compresed valuel "<<hexToUint64( readbalanceString(DataTransactionUncompressed , false));
        TransacElementCompression[1]=true;
        newCompressedtransac+=readbalanceString(DataTransactionUncompressed , false).substr(8,8);
    } else {

        TransacElementCompression[1]=false;
        newCompressedtransac+=readbalanceString(DataTransactionUncompressed , false);

    }

    //cout<<endl<<"transac compresed valuel "<<newCompressedtransac;

    // 3 accR Compress
    acc = accArr( accR );
    auto it2  = AccSync.find(acc);

    if (it2 != AccSync.end()){

        if(  AccSync[acc].DataCompressIndex!=0 &&  ( AccSync[acc].DataCompressIndex <= maxCompPoint ) ) {
            newCompressedtransac += uint16ToHex(AccSync[acc].DataCompressIndex)+compressAccStr(accR);
            TransacElementCompression[2]=true;
        } else { 

            //cout<<endl<<"debug bl compress accR - AccSync[acc].DataCompressIndex"<< AccSync[acc].DataCompressIndex;
            for(uint16_t i = 0 ; i <=lastTopTransac;i++){

                if(typebl(blksOP[i]) == "00" || typebl(blksOP[i]) == "04" || typebl(blksOP[i]) == "06"|| typebl(blksOP[i]) == "08"){

                    if (i == lastTopTransac){
                        newCompressedtransac += accR;
                        TransacElementCompression[2]=false;
                        AccSync[acc].DataCompressIndex=0;
                        break;
                    }
                    if(readaccountString(blksOP[i], false) == accR) {
                        newCompressedtransac +=uint16ToHex(0)+compressAccStr(accR);
                        TransacElementCompression[2]=true;
                        break;
                    }
                    if(readaccountString(blksOP[i], true)==accR) {
                        newCompressedtransac +=uint16ToHex(0)+compressAccStr(accR);
                        TransacElementCompression[2]=true;
                        break;
                    }
                }

            }

        }
    } else { 

        //handle the several internal memory error
    }
   // cout<<endl<<"transac compresed accr "<<newCompressedtransac;


    // 4 valueR Compress
    if(blktype != "04"){
        if ( hexToUint64( readbalanceString(DataTransactionUncompressed , true)) <=4294967295 ){
            TransacElementCompression[3]=true;
            newCompressedtransac+=readbalanceString(DataTransactionUncompressed , true).substr(8,8);
        } else {
            TransacElementCompression[3]=false;
            newCompressedtransac+=readbalanceString(DataTransactionUncompressed , true);
        }
    }else {
        TransacElementCompression[3]=false;
    }

    string definedtransac = definebltype(TransacElementCompression,blktype)+newCompressedtransac+DataTransactionUncompressed.substr(290,140);

    //cout<<endl<<"transac compresed is "<<definedtransac<< endl << endl;
    //cout<<endl<<"transac uncompresed is "<<DataTransactionUncompressed<< endl << endl;

    return definedtransac;
}

string compressTransac(string &DataTransactionUncompressed, uint16_t lastTopTransac){

    switch(TypeTransaction(DataTransactionUncompressed)){

        case 0x00:
        case 0x04:
        case 0x06:
        case 0x08:

            return compress0x00(DataTransactionUncompressed,lastTopTransac );
            break;

        case 0x0A:
        case 0x0C:

            return compress0x0A(DataTransactionUncompressed,lastTopTransac );
            break;

        default:
            exit_call();

    }

    return "Error compressTransac ";
 
}

uint16_t dataCompressIndex(uint64_t &lastBL,uint64_t &last,bool compressedPoint,uint16_t &CompressedPointBL){
    if(!compressedPoint){
        if( (lastBL<maxCompPoint || lastBL-last < maxCompPoint) && lastBL >= last){
            return lastBL-last;
        } else {return 65534;}
    } else{
        if( (lastBL-last)+CompressedPointBL < maxCompPoint && (lastBL-last)+CompressedPointBL >= CompressedPointBL && lastBL >= last){
            return (lastBL-last)+CompressedPointBL;
        } else {
            return 65534;}
    }
    return 0;
}

void AccIndexCompareCompressPointBuildVectorAccB3(vector<unsigned char>&bl2,vector<array<unsigned char,64>> &accB, uint &primerInit, uint8_t (&CompresedAcc)[4]) {

    array<unsigned char, 64> accRead;
    uint primer = primerInit;
    uint8_t bltype = DbTransaction[bl2[primer]].CompressTypeTransaction;

    if(!DbTransaction[bltype].AccLIsCompressed){

        for(uint8_t i = 0;i<2;i++){

            if(CompresedAcc[i+2]!=bl2[primer+i+DbTransaction[bltype].accLPos+62]){

                break;
            }
            if(i==1){
                for(uint8_t e = 0; e<64;e++){
                    accRead[e] = bl2[primer +e+DbTransaction[bltype].accLPos];
                }
                accB.push_back(accRead);
            }   
        }
    }

    if(!DbTransaction[bltype].AccRIsCompressed){

        for(uint8_t i = 0;i<2;i++){
            if(CompresedAcc[i+2]!=bl2[primer+i+DbTransaction[bltype].accRPos+62]){
                break;
            }
            if(i==1){
                for(uint8_t e = 0; e<64;e++){
                    accRead[e] = bl2[primer+e+DbTransaction[bltype].accRPos];
                }
               accB.push_back(accRead);
               
            }   
        }
    }
}

void AccIndexCompareCompressPointBuildVectorAccB2(vector<unsigned char>&bl2,vector<string> &accB, uint &primerInit, uint8_t (&CompresedAcc)[4]) {

    string accRead = "";
    uint primer = primerInit;
    uint8_t bltype = DbTransaction[bl2[primer]].CompressTypeTransaction;

    if(!DbTransaction[bltype].AccLIsCompressed){

        for(int i = 0;i<2;i++){

            if(CompresedAcc[i+2]!=bl2[primer+i+DbTransaction[bltype].accLPos+62]){
                break;
            }
            if(i==1){
                for(int e = 0; e<64;e++){
                    accRead += byteToHex2(bl2[primer +1+e]);
                }
                accB.push_back(accRead);
            }   
        }
    }

    accRead = "";

    if(!DbTransaction[bltype].AccRIsCompressed){

        for(int i = 0;i<2;i++){
            if(CompresedAcc[i+2]!=bl2[primer+i+DbTransaction[bltype].accRPos+62]){
                break;
            }
            if(i==1){
                for(int e = 0; e<64;e++){
                    accRead += byteToHex2(bl2[primer+e+DbTransaction[bltype].accRPos]);
                }
                accB.push_back(accRead);
            }   
        }
    }
}

//anade cuentas coincidentes con el compress point al vector de accs
void AccIndexCompareCompressPointBuildVectorAccB(vector<unsigned char>&bl2,vector<string> &accB, uint &primerInit, uint8_t (&CompresedAcc)[4]) {

    string accRead = "";
    uint primer = primerInit;
    uint8_t bltype = DbTransaction[bl2[primer]].CompressTypeTransaction;

    if(bltype==0x00||bltype==0x04|bltype==0x06||bltype==0x08||bltype==0x0E){

        for(int i = 0;i<2;i++){
            if(CompresedAcc[i+2]!=bl2[primer +63+i]){
                break;
            }
            if(i==1){
                for(int e = 0; e<64;e++){
                    accRead += byteToHex2(bl2[primer +1+e]);
                }
                accB.push_back(accRead);
            }   
        }
        for(int i = 0;i<2;i++){
            if(CompresedAcc[i+2]!=bl2[primer +135+i]){
                break;
            }
            if(i==1){
                for(int e = 0; e<64;e++){
                    accRead += byteToHex2(bl2[primer +73+e]);
                }
                accB.push_back(accRead);

            }
        }
        return ;
    }

    if(bltype==0x0B||bltype==0x11){
        for(int i = 0;i<2;i++){
            if(CompresedAcc[i+2]!=bl2[primer +75+i]){
                break;
            }
            if(i==1){
                for(int e = 0; e<64;e++){
                    accRead += byteToHex2(bl2[primer +13+e]);
                }
                accB.push_back(accRead);
                return;
            }
        }
        return ;
    }

    if(bltype==0x0C||bltype==0x13||bltype==0x14||bltype==0x15){
        for(int i = 0;i<2;i++){
            if(CompresedAcc[i+2]!=bl2[primer +63+i]){
                break;
            }
            if(i==1){
                for(int e = 0; e<64;e++){
                    accRead += byteToHex2(bl2[primer +1+e]);
                }
                accB.push_back(accRead);
                return;
            }
        }
        return ;
    }

    if(bltype==0x0D||bltype==0x0F){
        for(int i = 0;i<2;i++){
            if(CompresedAcc[i+2]!=bl2[primer +63+i]){
                break;
            }
            if(i==1){
                for(int e = 0; e<64;e++){
                    accRead += byteToHex2(bl2[primer +1+e]);
                }
                accB.push_back(accRead);
            }
        }
        for(int i = 0;i<2;i++){
            if(CompresedAcc[i+2]!=bl2[primer +131+i]){
                break;
            }
            if(i==1){
                for(int e = 0; e<64;e++){
                    accRead += byteToHex2(bl2[primer +69+e]);
                }
                accB.push_back(accRead);
            }
        }
        return ;
    }

    if(bltype==0x10||bltype==0x12){
        for(int i = 0;i<2;i++){
            if(CompresedAcc[i+2]!=bl2[primer +71+i]){
                break;
            }
            if(i==1){
                for(int e = 0; e<64;e++){
                    accRead += byteToHex2(bl2[primer +9+e]);
                }
                accB.push_back(accRead);
                return;
            }
        }
        return ;
    }



    return ;

}

bool buildAccbVector2(vector<array<unsigned char, 64>> &accB, uint64_t last, uint8_t (&compressedPoint)[4]){

    uint32_t qttblks;
    uint primerInit = 179;
    vector<unsigned char>bl2;
    uint16_t CompressBl = (static_cast<uint16_t>(compressedPoint[0]) << 8) | compressedPoint[1];
    uint8_t CompressAcc[2];
    //std::memcpy(CompressAcc, compressedPoint + 2, 2);

    if(CompressBl>last){
        cout<<endl<<"error buildAccbVectors CompressBl>last "<<CompressBl;
        return false;
    }

    last-=CompressBl;

    if(!build_blks( qttblks, last,  bl2)){
        return false;
    }

    for(uint a = qttblks; a>0 ; a--){ 
        
        AccIndexCompareCompressPointBuildVectorAccB3(bl2, accB, primerInit, compressedPoint);

        if(!PrimerChange(bl2[primerInit],primerInit)){
            cout<<endl<<"error buildAccbVector !PrimerChange"<<endl;
            exit_call();
        }
    }
    if(accB.size()>0){
        return true;
    } else {
        cout<<endl<<"error buildAccbVector() accB.size()<1 acc compressed is missing"<<endl; 
        return false;
    }
       
}  

bool buildAccbVector(vector<string> &accB, uint64_t last, uint8_t (&compressedPoint)[4]){

    uint32_t qttblks;
    uint primerInit = 179;
    vector<unsigned char>bl2;
    uint16_t CompressBl = (static_cast<uint16_t>(compressedPoint[0]) << 8) | compressedPoint[1];
    uint8_t CompressAcc[2];
    //std::memcpy(CompressAcc, compressedPoint + 2, 2);

    if(CompressBl>last){
        cout<<endl<<"error buildAccbVectors CompressBl>last "<<CompressBl;
        return false;
    }

    last-=CompressBl;



    if(!build_blks( qttblks, last,  bl2)){
        return false;
    }

    for(uint a = qttblks; a>0 ; a--){ 
        AccIndexCompareCompressPointBuildVectorAccB2(bl2, accB, primerInit, compressedPoint);
        if(!PrimerChange(bl2[primerInit],primerInit)){
            cout<<endl<<"error buildAccbVector !PrimerChange"<<endl;
            exit_call();
        }
    }
    if(accB.size()>0){
        return true;
    } else {
        cout<<endl<<"error buildAccbVector() accB.size()<1 acc compressed is missing"<<endl; 
        return false;
    }
       
}  

void getCompressedPointBlTransac2(vector<unsigned char> &bl2 , uint8_t (&compressedPoint)[4],uint &primer, bool side){

    uint8_t bltype = DbTransaction[bl2[primer]].CompressTypeTransaction;

    if(!side){

        for(int i =0; i<4;i++){
            compressedPoint[i]=bl2[primer+i+DbTransaction[bltype].accLPos];
        }
        return;

    } else{
        
        for(int i =0; i<4;i++){
            compressedPoint[i]=bl2[primer+i+DbTransaction[bltype].accRPos];
        }
        return;
    }

    return;

}

void getCompressedPointBlTransac(vector<unsigned char> &bl2 , uint8_t (&compressedPoint)[4],uint &primer, bool side){

    uint8_t bltype = DbTransaction[bl2[primer]].CompressTypeTransaction;

    if(bltype==0x0B||bltype==0x10||bltype==0x11|bltype==0x12|| (bltype==0x16&&!side )|| (bltype==0x17&&!side )|| (bltype==0x18&&!side )|| (bltype==0x19&&!side )){

        for(int i =0; i<4;i++){
            compressedPoint[i]=bl2[primer+i+1];
        }
        return;
    }
    if(bltype==0x0C||bltype==0x14){

        for(int i =0; i<4;i++){
            compressedPoint[i]=bl2[primer+i+73];
        }
        return;
    }
    if(bltype==0x13||bltype==0x15){

        for(int i =0; i<4;i++){
            compressedPoint[i]=bl2[primer+i+69];
        }
        return;
    }

    if(bltype==0x16||bltype==0x18){
        for(int i =0; i<4;i++){
            compressedPoint[i]=bl2[primer+i+13];
        }
        return;
    }

    if( bltype ==0x17||bltype==0x19){

        for(int i =0; i<4;i++){
            compressedPoint[i]=bl2[primer+i+9];
        }
        return;
    }

    return ;
}

bool searchUncompressAccInBl(array <unsigned char,64> acc, uint64_t last){

    uint qttblks;
    uint primerInit = 179;
    unsigned char DataTransac[247];
    unsigned char signature[64];
    array<unsigned char, 64> accB;
    vector<unsigned char>bl2;
    if(!build_blks( qttblks, last,  bl2)){
        return false;
    }
    for(uint a = qttblks; a>0 ; a--){ 

        uint8_t result = AccIndexCompare2(bl2,primerInit,  acc);

        if (result == 2 ||result == 1 ){
            return true;
        }

        PrimerChange(bl2[primerInit],primerInit);
    }
    return false;
} 

#endif
