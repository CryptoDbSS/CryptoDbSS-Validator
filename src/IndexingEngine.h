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

#ifndef INDEXINGENGINE_H
#define INDEXINGENGINE_H

#include "CryptoDbSS.cpp"

bool IsTypeConfirmed(uint8_t bltype);

void accBuilderCheckIter(unsigned char (&DataTransaction)[247], array<unsigned char,64> &SignerAcc, vector<array<unsigned char , 64>> accB, uint16_t accBelement, uint8_t &transactionDbType, bool side) {

    if(side){

        for (uint8_t i =0; i<64; i++){
            DataTransaction[TransactionDataFormat[DbTransaction[transactionDbType].TypeTransaction].POS_addressL_Bytes+i] = accB[accBelement][i];
            SignerAcc[i] = DataTransaction[TransactionDataFormat[DbTransaction[transactionDbType].TypeTransaction].POS_addressL_Bytes+i];
        }

    } else { 

        if(DbTransaction[transactionDbType].HaveAccR){

            for (uint8_t i =0; i<64; i++){
                DataTransaction[TransactionDataFormat[DbTransaction[transactionDbType].TypeTransaction].POS_addressR_Bytes+i] = accB[accBelement][i];
            }

        }

    }
}

string searchlastmoveCkBl2(vector<unsigned char> bl2, array<unsigned char, 64 > &acc,uint primerInit, uint64_t last, uint index){

    uint64_t rests = 0;
    uint64_t sums = 0;
    uint8_t result;
    vector<array<unsigned char, 64>> accB;
    uint16_t compressedNull;

	index--;

    PrimerChange(bl2[primerInit],primerInit);

    while (last>=0) {
		
		if(index<1){
            if(last < 1 ){
                break;
            }
			last--;
			if(!build_blks(index, last, bl2)){
                return "false";
			}
            primerInit =179;

            array<unsigned char, 64UL>accfeedblreaded = readAddressFeedBl(bl2);

            if( readAddressFeedBl(bl2) == acc){
                cout<<endl<<"slmck Acc found in blhead : "<<readAddressFeedBlBalance(bl2)<< endl;
                cout<<"in bl number  "<<last<< endl;
                if(rests> readAddressFeedBlBalance(bl2)+sums || readAddressFeedBlBalance(bl2)+sums  < readAddressFeedBlBalance(bl2) ){
                    cout<<endl<<"Error slm overflow Side block Head" <<endl;
                    exit_call();
                }
                return ullToHex((readAddressFeedBlBalance(bl2)+sums)-rests)+intToHex(last)+intToHex(0)+byteToHex(false)+byteToHex(false);
            }
		}

        for(index; index>0 ; index--){ 

            //  cout<<endl<<"Block build x "<< last;
            // cout<<endl<<"Block transac y["<< index <<"]"<<endl;

            result = AccIndexCompare33(bl2,primerInit, last, acc, accB,compressedNull);

            //compare accR
            if (result == 2){

               // cout <<endl<<"slm chksums search index result x: "<<last<<" y: "<<index<<" on AccRPoint" << endl;

                if(accB.size()<1){
                    cout<<endl<<"debug accB.size()<1";
                    exit_call();
                }
                unsigned char DataTransac[247];
                unsigned char signature[64];
                array<unsigned char,64> SignerAcc;
				
                buildTransacPointerFromBuffer3(bl2,acc,true, primerInit,last, DataTransac);
                builSignaturePointerFromBuffer2(bl2,primerInit,signature);

                uint16_t accBsize = accB.size();
                uint16_t accNumberVector;
                uint8_t CompressTypeTransaction = DbTransaction[bl2[primerInit]].CompressTypeTransaction;

                for( accNumberVector= 0; accNumberVector< accBsize; accNumberVector++){

                    accBuilderCheckIter(DataTransac, SignerAcc, accB, accNumberVector,CompressTypeTransaction, true );

                    //verify if the signature match with the data transac and acc
                    if(!verifySignatureCryptoPP(DataTransac, TransactionDataFormat[DataTransac[0]].size_TransactionOnlyData_Bytes, signature,accB[accNumberVector])){
                        if(accNumberVector==accBsize-1){
                            accNumberVector++;
                            break;
                        }
                    }else {
                        //cout<<endl<<"ckeck firm success";
                        break; 
                    }

                }



                if(accNumberVector==accBsize){
                    PrimerChange(bl2[primerInit],primerInit);
                    continue;
                }

                if( DataTransac[0] == 4 || DataTransac[0] == 6){
                    if(readbalanceFromDatatransacArray(DataTransac, true)>readbalanceFromDatatransacArray(DataTransac, true)+sums){
                        cout<<endl<<"Error slm overflow Side R"<<endl;
                        exit_call();
                    }
                    sums += readbalanceFromDatatransacArray(DataTransac, true);
                    PrimerChange(bl2[primerInit],primerInit);
                    continue;
                }
                                         
                return ullToHex((readbalanceFromDatatransacArray(DataTransac, true)+sums)-rests)+uint64ToHex(last)+uint16ToHex(index);
            }

            //compare accL
            if (result == 1){

                // cout <<endl<<"slm chksums search index result x: "<<last<<" y: "<<index<<" on AccLPoint" << endl;

                if(accB.size()<1 && DbTransaction[DbTransaction[bl2[primerInit]].CompressTypeTransaction].HaveAccR ){
                    cout<<endl<<"debug accB.size()<1";
                    exit_call();
                }
                unsigned char DataTransac[247];
                unsigned char signature[64];
                array<unsigned char,64> SignerAcc;

                buildTransacPointerFromBuffer3(bl2,acc,false, primerInit,last, DataTransac);
                builSignaturePointerFromBuffer2(bl2,primerInit,signature);


                uint16_t accBsize = accB.size();
                uint16_t accNumberVector;
                uint8_t CompressTypeTransaction = DbTransaction[bl2[primerInit]].CompressTypeTransaction ;

                if(!DbTransaction[DbTransaction[bl2[primerInit]].CompressTypeTransaction].HaveAccR){
                    accBsize = 1;
                }

                for( accNumberVector= 0; accNumberVector< accBsize; accNumberVector++){

                    accBuilderCheckIter(DataTransac, SignerAcc, accB, accNumberVector, CompressTypeTransaction, false);

                    if(!verifySignatureCryptoPP(DataTransac, TransactionDataFormat[DataTransac[0]].size_TransactionOnlyData_Bytes , signature, acc)){

                        if(accNumberVector==accBsize-1){
                            accNumberVector++;
                            break;
                        }
                    }else {
                        //<<endl<<"signature check success";
                        break; 
                    }

                }

                if(accNumberVector==accBsize){
                    PrimerChange(bl2[primerInit],primerInit);
                    continue;
                }

                if( DataTransac[0] == 0x04 || DataTransac[0] == 0x08 || DataTransac[0] == 0x0C ){
                    if(readbalanceFromDatatransacArray(DataTransac, false)>readbalanceFromDatatransacArray(DataTransac, false)+BuildFeedOfTransacFromArray(DataTransac)+rests
                    || readbalanceFromDatatransacArray(DataTransac, false)>readbalanceFromDatatransacArray(DataTransac, false)+BuildFeedOfTransacFromArray(DataTransac)
                    ){

                        cout<<endl<<"Error slm overflow Side L "<<endl;
                        exit_call();

                    }

                    if(DataTransac[0] == 0x0C){
                        rests += readbalanceFromDatatransacArray(DataTransac, false);
                    } else {
                        rests += readbalanceFromDatatransacArray(DataTransac, false)+BuildFeedOfTransacFromArray(DataTransac);
                    }
                    PrimerChange(bl2[primerInit],primerInit);
                    continue;
                    
                }

                return ullToHex((readbalanceFromDatatransacArray(DataTransac, false)+sums)-rests)+uint64ToHex(last)+uint16ToHex(index);
            }
       
            PrimerChange(bl2[primerInit],primerInit);
        }
    } 

    string balance;

    if(sums >0){
        if(rests>sums){
            return "error db sums";
        } else{balance = ullToHex(sums-rests);
        }
    }else{ balance = "0000000000000000"; } 

    return balance+intToHex(last)+intToHex(0)+byteToHex(false)+byteToHex(false);

}

bool checkSumsBalances(vector<unsigned char>bl2,array<unsigned char, 64> accA, unsigned char (&DataTransac)[247],array<unsigned char, 64> accB, uint &primer, uint64_t last, uint16_t &index,bool AccBside){

    string balanceAntL="";
    string balanceAntR="";
    uint64_t balanceantl;
    uint64_t balanceantr;
    string AccL="";
    string AccR="";

    uint64_t feed = BuildFeedOfTransacFromArray(DataTransac);

    if(!IsTypeConfirmed(DataTransac[0])){
        cout<<endl<<"error checkSumsBalances() !DataTransac[0] == 0 && !DataTransac[0] == 6 && !DataTransac[0] == 8 "<<byteToHex2(DataTransac[0])<<endl;
        exit_call();
        return false;
    }

    if(AccBside){
        AccR = builAccStringFromDataTransacArray(DataTransac, true);
        AccL = builAccStringFromDataTransacArray(DataTransac, false);
    }else{ 
        AccL = builAccStringFromDataTransacArray(DataTransac, false);
        AccR = builAccStringFromDataTransacArray(DataTransac, true);
    }

   // cout<<endl<<"debug checkSumsBalances pre account defining sides  AccL"<<AccL <<" AccR " <<AccR<<" acc side "<<to_string(AccBside)<<endl;
    
    uint64_t balanceR = readbalanceFromDatatransacArray(DataTransac,true);
    uint64_t balanceL = readbalanceFromDatatransacArray(DataTransac,false);

    if(DbTransaction[DataTransac[0]].HaveAccR){


        if(AccBside){

            balanceAntR = searchlastmoveCkBl2(bl2, accB,primer, last,  index);
            if( !HexCheck(balanceAntR) ){
                cout<<endl<<"error checkSumsBalances !HexCheck(balanceAntR) "<<balanceAntR<<endl;
                exit_call();
            }

            balanceAntL = searchlastmoveCkBl2(bl2, accA,primer, last,  index);
            if( !HexCheck(balanceAntL) ){
                cout<<endl<<"error checkSumsBalances !HexCheck(balanceAntL) "<<balanceAntL<<endl;
                exit_call();
            }

            balanceantl = hexToUint64(balanceAntL.substr(0 ,16));
            balanceantr = hexToUint64(balanceAntR.substr(0 ,16));

        } else {
            balanceAntL = searchlastmoveCkBl2(bl2, accB,primer, last,  index);
            if( !HexCheck(balanceAntL) ){
                cout<<endl<<"error checkSumsBalances !HexCheck(balanceAntL) "<<balanceAntL<<endl;
                exit_call();
            }
            
            balanceAntR = searchlastmoveCkBl2(bl2, accA,primer, last,  index);
            if( !HexCheck(balanceAntR) ){
                cout<<endl<<"error checkSumsBalances !HexCheck(balanceAntR) "<<balanceAntR<<endl;
                exit_call();
            }

            balanceantl = hexToUint64(balanceAntR.substr(0 ,16));
            balanceantr = hexToUint64(balanceAntR.substr(0 ,16));

        }

    } else {

        balanceAntL = searchlastmoveCkBl2(bl2, accA,primer, last,  index);
        if( !HexCheck(balanceAntL) ){
            cout<<endl<<"error checkSumsBalances !HexCheck(balanceAntL) "<<balanceAntL<<endl;
            exit_call();
        }

        balanceantl = hexToUint64(balanceAntL.substr(0 ,16));

    }

    if(DataTransac[0] == 0x04 ){     

        cout<<endl<<"CheckSums Transac | type 0x04"<<endl;
        cout<<"=================================== DB Sums: ======  Block Read: "<<last<<"  ====== Transac N : "<<index<<"  =============================================";
        cout<<endl<<"Acc L: "<<AccL;
        cout<<endl<<"Acc R: "<<AccR<<endl;
        cout<<"============================================================================="<<endl;
        cout<<"===  Acc L preBalance      "<< balanceantl<<endl;
        cout<<"===  Acc L Balance         "<<balanceL<<endl;
        cout<<"============================================================================="<<endl;
        cout<<"=== -Acc R balance         "<<balanceR<<endl;
        cout<<"=== -Acc R preBalance      "<<balanceantr<<endl;
        cout<<"============================================================================="<<endl;

        cout<<"============================================================================="<<endl;
        cout<<"=========Balance Ant L Found==========|==========Balance Ant R Found========="<<endl;
        cout<<"=            BN "<< hexToInt( balanceAntL.substr(16 ,16))<<" - TN "<< hexToInt(balanceAntL.substr(32 ,4))<< "       =     |           = BN "<< hexToInt(balanceAntR.substr(16 ,16))<<" - TN "<< hexToInt(balanceAntR.substr(32 ,4))<<endl;


        cout<<endl<<"balanceL "<<balanceL;
        cout<<endl<<"balanceR "<<balanceR;

        cout<<endl<<"balanceAntL "<<balanceantl;
        cout<<endl<<"balanceAntR "<<balanceantr;

        cout<<endl<<"feed of transac "<<feed<<endl;

        cout<<endl<<"hexToInt( balanceAntR.substr(16 ,16)) "<<hexToInt( balanceAntR.substr(16 ,16));

        if(balanceantl<balanceL+ feed || balanceL+ feed < balanceL || balanceL != balanceR ){
                    cout<<endl<<" checksums DB Fail! 0004"<<endl;
            return false;
        } else { 
            return true;
        }

    }

    if(DataTransac[0] == 0x06 ){

        cout<<endl<<"acc L: "<<AccL;
        cout<<endl<<"acc R: "<<AccR<<endl;

        cout<<"==== DB Sums: ======  Block Read: "<<last<<"  ====== Transac N : "<<index+1<<"  ====== Opt:   ==="<<endl;
        cout<<"============================================================================="<<endl;
        cout<<"===  balanceAntL "<< balanceantl<<" ====|===  Sum R side    ===="<<endl;
        cout<<"=== -balanceL    "<<balanceL<<" ====|======== "<<balanceR<<" ===="<<endl;
        cout<<"===_______________________________====|===_______________________________===="<<endl;
        cout<<"==== result      "<<balanceantl-balanceL<<" ====|================ "<< balanceR<<"====="<<endl;
        cout<<"============================================================================="<<endl;
        cout<<"=========Balance Ant L Found==================="<<endl;
        cout<<"=       BR "<< hexToInt( balanceAntL.substr(16 ,8))<<" = TN "<< hexToInt(balanceAntL.substr(24 ,8))<<" = OpT: "<<balanceAntL.substr(32 ,2)<<endl;
            cout<<endl<<"feed of transac "<<feed<<endl;

        if( balanceantl-(balanceL+feed) != balanceR || balanceL+feed > balanceantl 
        || balanceL+feed < balanceL || balanceantr >  balanceR
        ){
                    cout<<endl<<" checksums DB Fail! 0006"<<endl;
            return false;
        } else { return true;}

    }

    if(DataTransac[0] == 0x08 ){     

        cout<<endl<<"acc L: "<<AccL;
        cout<<endl<<"acc R: "<<AccR<<endl;

        cout<<"==== DB Sums: ======  Block Read: "<<last<<"  ====== Transac N : "<<index+1<<"  ====== Opt:   ==="<<endl;
        cout<<"============================================================================="<<endl;
        cout<<"==========  Sum L side    ===========  balanceR    "<<balanceR<<" ===="<<endl;
        cout<<"=== -balanceL    "<<balanceL<<" ====|=== -balanceAntR "<<balanceantr<<" ===="<<endl;
        cout<<"===_______________________________====|===_______________________________===="<<endl;
        cout<<"==== result      "<<balanceL<<" ====|================ "<< balanceR-balanceantr<<"====="<<endl;
        cout<<"============================================================================="<<endl;
        cout<<"==========Balance Ant R Found========="<<endl;
        cout<< "             = BR "<< hexToInt(balanceAntR.substr(16 ,8))<<" = TN "<< hexToInt(balanceAntR.substr(24 ,8))<<" = OpT: "<<balanceAntR.substr(32 ,2)<<endl;

        cout<<endl<<"feed of transac "<<feed<<endl;

        if(balanceR-balanceantr != balanceL+feed 
        || balanceL+feed<balanceL || balanceantl<balanceL+feed  || balanceR-balanceantr>balanceR
        || balanceR < balanceantr ){
                    cout<<endl<<" checksums DB Fail! 0008"<<endl;
            return false;
        } else { return true;}

    }

    if(DataTransac[0] == 0x0A ){

        cout<<endl<<" balanceantl "<<balanceantl<<"  BN "<< hexToInt( balanceAntL.substr(16 ,16))<<" - TN "<< hexToInt(balanceAntL.substr(32 ,4))
        <<endl<<" balanceL "<< balanceL<< " feed "<<feed<<" BN: "<<last<<" - TN "<<index<< endl;

        if(balanceantl-balanceL != feed || balanceantl < balanceL){
            cout<<endl<<" checksums DB Fail! 000A"<<endl;
            return false;
        } else { return true;}

    }

    if(DataTransac[0] == 0x0C ){

        if(balanceantl < feed || balanceantl < balanceL){
             cout<<endl<<" checksums DB Fail! 000C"<<endl;
             return false;
        } else { return true;}

    }

    balanceantl = hexToULL(balanceAntL.substr(0 ,16));
    balanceantr = hexToULL(balanceAntR.substr(0 ,16));

    cout<<endl<<"CheckSums Transac | type 0x00"<<endl;
    cout<<"=================================== DB Sums: ======  Block Read: "<<last<<"  ====== Transac N : "<<index<<"  =============================================";
    cout<<endl<<"Acc L: "<<AccL;
    cout<<endl<<"Acc R: "<<AccR<<endl;
    cout<<"============================================================================="<<endl;
    cout<<"===  Acc L preBalance      "<< balanceantl<<endl;
    cout<<"===  Acc L Balance         "<<balanceL<<endl;
    cout<<"============================================================================="<<endl;
    cout<<"=== -Acc R balance         "<<balanceR<<endl;
    cout<<"=== -Acc R preBalance      "<<balanceantr<<endl;
    cout<<"============================================================================="<<endl;
    cout<<"==== Result    Acc L sums  "<< balanceantl-(balanceL+feed) <<endl<<
          "               Acc R sums  "<< balanceR-balanceantr<<"====="<<endl;
    cout<<"============================================================================="<<endl;
    cout<<"=========Balance Ant L Found==========|==========Balance Ant R Found========="<<endl;
    cout<<"=            BN "<< hexToInt( balanceAntL.substr(16 ,16))<<" - TN "<< hexToInt(balanceAntL.substr(32 ,4))<< "       =     |           = BN "<< hexToInt(balanceAntR.substr(16 ,16))<<" - TN "<< hexToInt(balanceAntR.substr(32 ,4))<<endl;

    cout<<endl<<"feed of transac "<<feed<<endl;

    cout<<endl<<"balanceL "<<balanceL;
    cout<<endl<<"balanceR "<<balanceR;

    cout<<endl<<"balanceAntL "<<balanceantl;
    cout<<endl<<"balanceAntR "<<balanceantr;


    if( ((balanceantl-( balanceL+feed) != balanceR-balanceantr )  

        || balanceL+feed < balanceL || (balanceL+feed)>=balanceantl || balanceR<=balanceantr 

        || (balanceL + feed +(balanceR-balanceantr) !=  balanceantl) 

        || (balanceL + feed +(balanceR-balanceantr) <balanceL)
        || (balanceL + feed +(balanceR-balanceantr) <balanceR-balanceantr)
        
        ) && lastbl>0

    )
        {

        cout<<endl<<" checksums DB Fail! "<<endl;
        return false;
    }

    cout<<endl<<endl<<"Checksum DB OK "<<endl;
    return true;
}

string searchlastmove(string acctpubk , bool IsAccSync){

    cout<<endl<<" account indexing algorithm init: "<<acctpubk;

    const uint64_t lastBL = lastbl;
    extern bool Refactorizing;

    if(Refactorizing){
        return "refactorizing new block, try again in a few moments";
    }

    if( !HexCheck(acctpubk)){ 
        cout<<endl<<"invalid address format character  "<<acctpubk<<endl;
        return "invalid address format character" ;
    }
    if( acctpubk.length() == 130 && acctpubk.substr(0,2) == "04"){
        acctpubk = acctpubk.substr(2,128);
    } else {
        if(acctpubk.length() != 128 ){
            cout<<endl<<"invalid lenght address "<<acctpubk<<endl;
            return "invalid lenght address " ;
        }
    }

    for (auto &s : acctpubk){s = toupper(s);}
    extern map< array <unsigned char,64>, dbstruct >mapIndex;
    extern map< array <unsigned char,64>, Accsync >AccSync;
    extern uint accIndexMaxCache;
    extern mutex WritingAccSync;
    array<unsigned char, 64 > acc = accArr( acctpubk);
    string balance;

    //If the thread is called and another process calls it again, it will block until the first process finishes this section.
    //////////////////////////////////////////////////////////////////////

    std::unique_lock<std::mutex> indexinglock(mapIndex[acc].indexingmtx);
    std::unique_lock<std::mutex> WritingAccSynclock(WritingAccSync);

    mapIndex[acc].indexing = true;


    //syncronic thread
    ////////////////////////////////////////////////////////////////////////////////

    if(IsAccSync){
        auto iter  = AccSync.find(acc);
        if (iter != AccSync.end()){
            if(AccSync[acc].indexed == true){
                cout<<endl<<"cache-indexed account : "<<acctpubk<<" value : "<<AccSync[acc].value;
                balance = ullToHex(AccSync[acc].value);
                mapIndex[acc].indexing = false;
                return balance;
            }
        }
    }

    auto iter  = AccSync.find(acc);
    if (iter != AccSync.end()){
        if(AccSync[acc].indexed){ 
            cout<<endl<<"cache-indexed account : "<<acctpubk<<" value : "<<AccSync[acc].value;
            balance = ullToHex(AccSync[acc].value);
            mapIndex[acc].indexing = false;
            return balance;
        }
    }

    auto it  = mapIndex.find(acc);
    if (it != mapIndex.end()){
        if(mapIndex[acc].indexed==true){
            if(IsAccSync){

                    AccSync[acc].value = mapIndex[acc].balance;
                    AccSync[acc].valueAnt = mapIndex[acc].balance;
                    AccSync[acc].DataCompressIndex = mapIndex[acc].DataCompressIndex;
                    cout<<endl<<"cache-indexed account : ";
                    balance = ullToHex(mapIndex[acc].balance);
                    AccSync[acc].indexed = true;
                    mapIndex[acc].indexing = false;
                    return balance;
                
            }
            cout<<endl<<"cache-indexed account";
            mapIndex[acc].indexing = false;
            balance = ullToHex(mapIndex[acc].balance);
            return balance;
        }
    } 

    if(mapIndex.size()>accIndexMaxCache){
        vector< array<unsigned char, 64 >> AccKeys;
        uint countermapCache = mapIndex.size();
        for (auto const& x : mapIndex){
            if(countermapCache>accIndexMaxCache&& accIndexMaxCache>0){
                if(!mapIndex[x.first].indexing){
                    AccKeys.push_back(x.first);
                    countermapCache--;
                }
            }
        }
        for (auto key : AccKeys) {
            cout<<endl<<"mapIndex.size()>=accIndexMaxCache erasing last index free memory";
            mapIndex.erase(key);
        }
    }

    mapIndex[acc].indexed = false;
    WritingAccSynclock.unlock();

    
    // End Sync lock Section
    ////////////////////////////////////////////////////////////////////////////////////////////

    cout<<endl<<"Acc is not indexed in cache, starting to search in DB...";

    uint64_t last = lastBL;
    uint qttblks;
    uint64_t rests = 0;
    uint64_t sums = 0;
    vector<unsigned char> bl2;
    uint primerInit = 179;
    uint16_t compressPoint=0;
    bool AccIndexFound = false;
    uint16_t lastcompressPoint;
    vector<array<unsigned char, 64>> accB;

    while (last>=0) {

        primerInit = 179;

        if(!build_blks( qttblks, last,  bl2)){

            WritingAccSynclock.lock();
            mapIndex[acc].indexed = false;
            mapIndex[acc].indexing = false;
            return "error reading DB";
        }

        array<unsigned char, 64UL>accfeedblreaded = readAddressFeedBl(bl2);

        if( readAddressFeedBl(bl2) == acc ){

            cout<<endl<<"account found in the Block Head";

            if(rests> readAddressFeedBlBalance(bl2)+sums || readAddressFeedBlBalance(bl2)+sums  < readAddressFeedBlBalance(bl2) ){

                cout<<endl<<"Error slm overflow Side block Head -  acc: "<<acctpubk;
                exit_call();

            }

            WritingAccSynclock.lock();
            
            if(Refactorizing|| lastBL !=lastbl){
                mapIndex[acc].indexing = false;
                return "refactorizing new block, try again in a few moments";
            }

            mapIndex[acc].balance = (readAddressFeedBlBalance(bl2)+sums)-rests ;
            mapIndex[acc].DataCompressIndex = 65535;
                if(IsAccSync){
                    AccSync[acc].value = mapIndex[acc].balance;
                    AccSync[acc].valueAnt = mapIndex[acc].balance;
                    AccSync[acc].DataCompressIndex = mapIndex[acc].DataCompressIndex;
                    AccSync[acc].indexed = true;
                }
            mapIndex[acc].indexing = false;
            mapIndex[acc].indexed = true;
            balance = ullToHex(mapIndex[acc].balance);
            return balance;

        }

        for(uint16_t a = qttblks; a>=1 ; a--){ 

            //  cout<<endl<<"slm Block Read N "<< last<< " transaction N["<< a <<"]"<<endl;

            uint8_t result = AccIndexCompare33(bl2,primerInit, last, acc, accB,compressPoint);

            //if acc is found on accRPoinr
            if (result == 2){

                //cout <<endl<<"slm search index result x: "<<last<<" y: "<<a<<" on AccRPoint" << endl;

                if(accB.size()<1){
                    cout<<endl<<"debug accB.size()<1";
                    exit_call();
                }
                unsigned char DataTransac[247];
                unsigned char signature[64];
                array<unsigned char,64> SignerAcc;
				
                buildTransacPointerFromBuffer3(bl2,acc,true, primerInit,last, DataTransac);
                builSignaturePointerFromBuffer2(bl2,primerInit,signature);

                uint16_t accBsize = accB.size();
                uint16_t accNumberVector;
                uint8_t CompressTypeTransaction = DbTransaction[bl2[primerInit]].CompressTypeTransaction;

                for( accNumberVector= 0; accNumberVector< accBsize; accNumberVector++){

                    accBuilderCheckIter(DataTransac, SignerAcc, accB, accNumberVector,CompressTypeTransaction, true );

                    //verify if the signature match with the data transac and acc
                    if(!verifySignatureCryptoPP(DataTransac, TransactionDataFormat[DataTransac[0]].size_TransactionOnlyData_Bytes, signature,accB[accNumberVector])){
                        if(accNumberVector==accBsize-1){
                            accNumberVector++;
                            break;
                        }
                    }else {
                        //cout<<endl<<"ckeck firm success";
                        break; 
                    }

                }

                
                if(accNumberVector==accBsize){
                    PrimerChange(bl2[primerInit],primerInit);
                    continue;
                }

                if(!AccIndexFound){
                    lastcompressPoint = compressPoint;
                    AccIndexFound=true;
                }

                //cout<<endl<<"acc R found i: "<< a <<" bl: "<<last<<" bltype "<<to_string(DataTransac[0])<<endl;
                //cout<<endl<<" debug slm sums R "<<to_string(sums)<<" rests "<<to_string(rests)<< " balance read "<<readbalanceFromDatatransacArray(DataTransac, true)<<endl;

                if( DataTransac[0] == 4 || DataTransac[0] == 6){
                    if(readbalanceFromDatatransacArray(DataTransac, true)>readbalanceFromDatatransacArray(DataTransac, true)+sums){
                        cout<<endl<<"Error slm overflow Side R -  acc: "<<acctpubk<<endl;
                        exit_call();
                    }
                    sums += readbalanceFromDatatransacArray(DataTransac, true);
                    PrimerChange(bl2[primerInit],primerInit);
                    continue;
                }

                if(rests>readbalanceFromDatatransacArray(DataTransac, true)+sums ){
                    if(readbalanceFromDatatransacArray(DataTransac, true)>readbalanceFromDatatransacArray(DataTransac, true)+sums){
                        cout<<endl<<"Error slm readbalanceFromDatatransacArray(DataTransac, true)>readbalanceFromDatatransacArray(DataTransac, true)+sums Side R -  acc: "<<acctpubk<<endl;
                    }
                    cout<<endl<<"Error slm rests>readbalanceFromDatatransacArray(DataTransac, true)+sums Side R -  acc: "<<acctpubk<<endl;
                    exit_call();
                }

                if(!checkSumsBalances(bl2,acc,DataTransac, accB[accNumberVector] ,primerInit, last, a, false)){
                    
                    WritingAccSynclock.lock();
                    mapIndex[acc].indexed = false;
                    mapIndex[acc].indexing = false;
                    return "Err";
                }

                WritingAccSynclock.lock();

                if(Refactorizing || lastBL !=lastbl){
                    mapIndex[acc].indexing = false;
                    return "refactorizing new block, try again in a few moment";
                }

                mapIndex[acc].balance = (readbalanceFromDatatransacArray(DataTransac, true)+sums)-rests;
                mapIndex[acc].DataCompressIndex = lastcompressPoint+1 ;
                mapIndex[acc].indexed = true;
                mapIndex[acc].indexing = false;

               // cout<<endl<<"debug mapIndex balance "<<to_string(mapIndex[acc].balance)<<endl;

                if(IsAccSync){
                    AccSync[acc].value = mapIndex[acc].balance;
                    AccSync[acc].valueAnt= mapIndex[acc].balance;
                    AccSync[acc].DataCompressIndex = mapIndex[acc].DataCompressIndex;
                    AccSync[acc].indexed = true;
                }
                balance = ullToHex(mapIndex[acc].balance);

                return balance;
            }
       
            //if acc is found on accLPoinr
            if (result == 1){

                //cout <<endl<<"slm search index result x: "<<last<<"y: "<<a<<" on AccLPoint" << endl;
                if(accB.size()<1 && DbTransaction[DbTransaction[bl2[primerInit]].CompressTypeTransaction].HaveAccR ){
                    cout<<endl<<"debug accB.size()<1";
                    exit_call();
                }
                unsigned char DataTransac[247];
                unsigned char signature[64];
                array<unsigned char,64> SignerAcc;

                buildTransacPointerFromBuffer3(bl2,acc,false, primerInit,last, DataTransac);
                builSignaturePointerFromBuffer2(bl2,primerInit,signature);

                if(!DbTransaction[DbTransaction[bl2[primerInit]].CompressTypeTransaction].HaveAccR){
                    accB.push_back(acc);
                }

                uint16_t accBsize = accB.size();
                uint16_t accNumberVector;
                uint8_t CompressTypeTransaction = DbTransaction[bl2[primerInit]].CompressTypeTransaction;

                for( accNumberVector= 0; accNumberVector< accBsize; accNumberVector++){

                    accBuilderCheckIter(DataTransac, SignerAcc, accB, accNumberVector,CompressTypeTransaction, false );

                    if(!verifySignatureCryptoPP(DataTransac, TransactionDataFormat[DataTransac[0]].size_TransactionOnlyData_Bytes , signature, acc)){

                        if(accNumberVector==accBsize-1){
                            accNumberVector++;
                            break;
                        }
                    }else {
                        //cout<<endl<<"signature check success";
                        break; 
                    }


                }

                if(accNumberVector==accBsize){
                    PrimerChange(bl2[primerInit],primerInit);
                    continue;
                }

               // cout<<endl<<"acc L found i: "<< a <<" bl: "<<last<<" bltype "<<to_string(DataTransac[0])<<endl;
               // cout<<endl<<" debug slm sums L "<<to_string(sums)<<" rests "<<to_string(rests)<< " balance read "<<readbalanceFromDatatransacArray(DataTransac, false)<<endl;

                if(!AccIndexFound){
                    lastcompressPoint = compressPoint;
                    AccIndexFound=true;
                } 

                if( DataTransac[0] == 0x04 || DataTransac[0] == 0x08 || DataTransac[0] == 0x0C){
                    if(readbalanceFromDatatransacArray(DataTransac, false)>readbalanceFromDatatransacArray(DataTransac, false)+BuildFeedOfTransacFromArray(DataTransac)+rests
                    || readbalanceFromDatatransacArray(DataTransac, false)>readbalanceFromDatatransacArray(DataTransac, false)+BuildFeedOfTransacFromArray(DataTransac)
                    ){

                        cout<<endl<<"Error slm overflow Side L -  acc: "<<acctpubk<<endl;
                        exit_call();

                    }
                    if(DataTransac[0] == 0x0C){
                        rests += readbalanceFromDatatransacArray(DataTransac, false);
                    } else {
                        rests += readbalanceFromDatatransacArray(DataTransac, false)+BuildFeedOfTransacFromArray(DataTransac);
                    }
                    PrimerChange(bl2[primerInit],primerInit);
                    continue;
                }

                if(rests> readbalanceFromDatatransacArray(DataTransac, false)+sums || readbalanceFromDatatransacArray(DataTransac, false)+sums  < readbalanceFromDatatransacArray(DataTransac, false) ){

                    if(readbalanceFromDatatransacArray(DataTransac, false)>readbalanceFromDatatransacArray(DataTransac, false)+sums){
                        cout<<endl<<"Error slm readbalanceFromDatatransacArray(DataTransac, false)>readbalanceFromDatatransacArray(DataTransac, false)+sums Side L -  acc: "<<acctpubk<<endl;
                    }
                    cout<<endl<<"Error slm rests> readbalanceFromDatatransacArray(DataTransac, false) Side L -  acc: "<<acctpubk<<endl;
                    exit_call();

                }

                if(!checkSumsBalances(bl2,acc,DataTransac,accB[accNumberVector], primerInit, last, a, true)){
                    WritingAccSynclock.lock();
                    mapIndex[acc].indexed = false;
                    mapIndex[acc].indexing = false;
                    return "Err";
                }

                WritingAccSynclock.lock();
                if(Refactorizing|| lastBL !=lastbl){
                    mapIndex[acc].indexing = false;
                    return "refactorizing new block, try again in a few moment";
                }

                mapIndex[acc].balance = (readbalanceFromDatatransacArray(DataTransac, false)+sums)-rests;
                mapIndex[acc].DataCompressIndex = lastcompressPoint+1 ;
                mapIndex[acc].indexed = true;
                mapIndex[acc].indexing = false;


                if(IsAccSync){
                    AccSync[acc].value = mapIndex[acc].balance;
                    AccSync[acc].valueAnt= mapIndex[acc].balance;
                    AccSync[acc].DataCompressIndex = mapIndex[acc].DataCompressIndex;
                    AccSync[acc].indexed = true;
                }

                balance = ullToHex(mapIndex[acc].balance);

                return balance;
            }

            PrimerChange(bl2[primerInit],primerInit);

        }
       
        if(last <= 0 ){
            break;
        }
        last--;
    } 



    WritingAccSynclock.lock();
    
    if(sums >0){
        if(rests>sums){
            mapIndex[acc].indexing = false; 
            return "error db sums";
        } else{balance = ullToHex(sums-rests);
              }
    }else{ balance = "0000000000000000"; 
        }

    if(Refactorizing|| lastBL !=lastbl){
        mapIndex[acc].indexing = false;
        return "refactorizing new block, try again in a few moment";
    }

    mapIndex[acc].indexed = true;
    mapIndex[acc].balance = hexToULL(balance);
    mapIndex[acc].indexing = false; 
    mapIndex[acc].DataCompressIndex = 65535;

    if(IsAccSync){

        AccSync[acc].value = mapIndex[acc].balance;
        AccSync[acc].valueAnt= mapIndex[acc].balance;
        AccSync[acc].DataCompressIndex = mapIndex[acc].DataCompressIndex;
        AccSync[acc].indexed = true;
        
    }

    return balance;
}

string searchtransac(string &hash){

    vector<unsigned char> bl2;
    uint16_t qttblks ;
    uint primer = 179;

    vector<unsigned char> HashReq = HexStrToBytes(hash);

    vector<array<unsigned char, 64>> accA;
    vector<array<unsigned char, 64>> accB;

    cout<<endl<<" hash req search "<<endl;
    for(uint8_t i= 0 ; i < HashReq.size() ;i++){
        cout<<byteToHex(HashReq[i]);
    }

    cout<<endl;

    for(uint64_t blnmbr = lastbl; blnmbr>=1; blnmbr--){

        blread2(to_string(blnmbr),bl2);
        primer = 179;
        qttblks = hexToULL(blkscontain2(bl2));
        vector<unsigned char>DataTransaction ;

        for(uint16_t transacnmbr = qttblks; transacnmbr>=1;transacnmbr--){

            DataTransaction.clear();
            accsvectorbuilder2(bl2,blnmbr, primer,accA,accB);
            buildTransacInVector(accA, accB, bl2,primer, blnmbr, transacnmbr, DataTransaction);

            vector<unsigned char>debughash = sha3_256v(DataTransaction);

            if(sha3_256v(DataTransaction)==HashReq){
                return byteVectorToHexStr(DataTransaction);
            }

            PrimerChange(bl2[primer],primer );
        }
            
    }



    return "Not Found in DB";

}



#endif
