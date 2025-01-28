/*
 * Software Name: CryptoDbSS
 * Copyright (C) 2025 Steeven J Salazar.
 * License: CryptoDbSS: Software Review and Audit License
 * 
 * https://github.com/Steeven512/CryptoDbSS
 *
 * IMPORTANT: Before using, compiling or do anything with this software, 
 * you must read and accept the terms of this License.
 * 
 * This software is provided "as is," without warranty of any kind.
 * For more details, see the LICENSE file.
 */


/* 
 
The CryptoDbSS, blockchain-core, consensus, protocols and misc.

This software is a prototype version, it should only be used for 
development, testing, study and auditing proporses. 

Third-party dependencies: CrowCpp, Crypto++, OpenSSL, Boost, ASIO, libcurl.

questions, suggestions or contact : Steevenjavier@gmail.com

*/

#ifndef INDEXINGENGINE_H
#define INDEXINGENGINE_H

#include "CryptoDbSS.cpp"


string searchlastmoveCkBl2(vector<unsigned char> bl2, array<unsigned char, 64 > &acc,uint primerInit, uint64_t last, uint index){

  //  cout<<endl<<"slmck2 debug init "<<endl;

    uint64_t rests = 0;
    uint64_t sums = 0;
    uint8_t result;
    vector<string> accB;
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
            cout<<endl<<"debug bl head search index  readAddressFeedBl(bl2) : "<<endl;
            for(uint8_t i = 0 ; i<64; i++){
                cout<<byteToHex2(accfeedblreaded[i]);
            }
            cout<<endl;
            for(uint8_t i = 0 ; i<64; i++){
                cout<< byteToHex2(acc[i]);
            }

            cout<<endl;

            if( readAddressFeedBl(bl2) == acc){
                cout<<endl<<"se encontro la cuenta en el bl head : "<<readAddressFeedBlBalance(bl2)<< endl;
                cout<<"in bl number  "<<last<< endl;
                readAddressFeedBlBalance(bl2);
                return ullToHex(readAddressFeedBlBalance(bl2))+intToHex(last)+intToHex(0)+byteToHex(false)+byteToHex(false);
            }
		}

        for(index; index>0 ; index--){ 

            //cout<<endl<<"Block build x "<< last;
            //cout<<endl<<"Block transac y["<< index <<"]"<<endl;

            result = AccIndexCompare3(bl2,primerInit, last, acc, accB,compressedNull);

            //compare accR
            if (result == 2){

                //cout <<endl<<"slm chksums search index result x: "<<last<<"y: "<<index<<" on AccRPoint" << endl;

                if(accB.size()<1){
                    cout<<endl<<"Error searchlastmoveCkBl2 result == 2 accB.size()<1";
                    exit_call();

                }
                unsigned char DataTransac[247];
                unsigned char signature[64];

				string datatransacstring="";
                string signaturestring="";
				
                buildTransacPointerFromBuffer(bl2,acc,primerInit,last, DataTransac);
                builSignaturePointerFromBuffer(bl2,primerInit,signature);

                //cout<<endl<<"debug data transac: "<<endl;
                for(int i =0;i<247;i++){
                    datatransacstring +=byteToHex(DataTransac[i]);
                   // cout<<byteToHex(DataTransac[i]);
                }
               // cout<<endl<<"debug data signature: "<<endl;
                for(int i =0;i<64;i++){
                   // cout<<byteToHex(signature[i]);
                    signaturestring+=byteToHex(signature[i]);
                }

                for (auto &s : datatransacstring){s = toupper(s);}
                for (auto &s : signaturestring){s = toupper(s);}

                uint16_t accBsize = accB.size();
                uint16_t accNumberVector;
                for(int accNumberVector = 0; accNumberVector< accBsize; accNumberVector++){

                    datatransacstring = datatransacstring.substr(0,2)+accB[accNumberVector].substr(0,128)+datatransacstring.substr(130,datatransacstring.length()-130);
                    for (auto &s : datatransacstring){s = toupper(s);}

                   // cout<<endl<<"data transac debug "<<datatransacstring<<endl<<endl;

                    if(!verifySignature(  datatransacstring, signaturestring, loadPublicKey(datatransacstring.substr(2,128) ))){

                        if(accNumberVector==accBsize-1){
                            accNumberVector++;
                            break;
                            cout<<endl<<"Error searchlastmoveCkBl2 Signature Invalid"<<endl;
                            exit_call();
                            return "DB Corrupt!, Firm False";
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
                    sums += readbalanceFromDatatransacArray(DataTransac, true);
                    PrimerChange(bl2[primerInit],primerInit);
                    continue;
                }
                                         
                return ullToHex((readbalanceFromDatatransacArray(DataTransac, true)+sums)-rests)+uint64ToHex(last)+uint16ToHex(index);
            }

            if (result == 1){

                //cout <<endl<<"slm chksums search index result x: "<<last<<"y: "<<index<<" on AccLPoint" << endl;

                if(accB.size()<1){
                    cout<<endl<<"Error searchlastmoveCkBl2  result == 1 accB.size()<1";
                    exit_call();
                }

                unsigned char DataTransac[247];
                unsigned char signature[64];

				string datatransacstring="";
                string signaturestring="";
				
                buildTransacPointerFromBuffer(bl2,acc,primerInit,last, DataTransac);
                builSignaturePointerFromBuffer(bl2,primerInit,signature);

                //cout<<endl<<"debug data transac: "<<endl;
                for(int i =0;i<247;i++){
                    datatransacstring +=byteToHex2(DataTransac[i]);
                   // cout<<byteToHex2(DataTransac[i]);
                }
               // cout<<endl<<"debug data signature: "<<endl;
                for(int i =0;i<64;i++){
                   // cout<<byteToHex2(signature[i]);
                    signaturestring+=byteToHex2(signature[i]);
                }

                uint16_t accBsize = accB.size();
                uint16_t accNumberVector;
                for(int accNumberVector = 0; accNumberVector< accBsize; accNumberVector++){

                    datatransacstring = datatransacstring.substr(0,146)+accB[accNumberVector].substr(0,128)+datatransacstring.substr(274,datatransacstring.length()-274);
                    for (auto &s : datatransacstring){s = toupper(s);}

                    //cout<<endl<<"data transac debug "<<datatransacstring<<endl<<endl;

                    if(!verifySignature(  datatransacstring, signaturestring, loadPublicKey(datatransacstring.substr(2,128) ))){

                        if(accNumberVector==accBsize-1){
                            accNumberVector++;
                            break;
                            cout<<endl<<"Error searchlastmoveCkBl2 Signature invalid"<<endl;
                            return "DB Corrupt!, Firm False";
                        }
                    }else {
                       // cout<<endl<<"ckeck firm success";
                        break; 
                    }

                }

                if(accNumberVector==accBsize){
                    PrimerChange(bl2[primerInit],primerInit);
                    continue;
                }

                if( DataTransac[0] == 4 || DataTransac[0] == 8){
                    rests += readbalanceFromDatatransacArray(DataTransac, false)+BuildFeedOfTransacFromArray(DataTransac);
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
            if(rests>sums){return "error db sums";
                } else{balance = ullToHex(sums-rests);
            }
    }else{ balance = "0000000000000000"; } 

    return balance+intToHex(last)+intToHex(0)+byteToHex(false)+byteToHex(false);

}

bool checkSumsBalances(vector<unsigned char>bl2,array<unsigned char, 64> accA, unsigned char (&DataTransac)[247],string &AccBStr, uint &primer, uint64_t last, uint16_t &index,bool AccBside){

    array<unsigned char, 64> accB= accArr(AccBStr);
    string balanceAntL;
    string balanceAntR;
    uint64_t balanceantl ;
    uint64_t balanceantr ;
    string AccL;
    string AccR;
    uint feed = BuildFeedOfTransacFromArray(DataTransac);

    if(AccBside){
        AccR = AccBStr;
        AccL = builAccStringFromDataTransacArray(DataTransac, false);
    }else{ 
        AccL = AccBStr;
        AccR = builAccStringFromDataTransacArray(DataTransac, true);
    }
    
    uint64_t balanceR = readbalanceFromDatatransacArray(DataTransac,true);
    uint64_t balanceL = readbalanceFromDatatransacArray(DataTransac,false);

    if(DataTransac[0] != 0x00 && DataTransac[0] != 0x04 && DataTransac[0] != 0x06 && DataTransac[0] != 0x08 ){
        cout<<endl<<"error checkSumsBalances() !DataTransac[0] == 0 && !DataTransac[0] == 6 && !DataTransac[0] == 8 "<<byteToHex2(DataTransac[0])<<endl;
        exit_call();
        return false;
    }

    if(AccBside){
        balanceAntL = searchlastmoveCkBl2(bl2, accA,primer, last,  index);
        if( !HexCheck(balanceAntL) ){
            cout<<endl<<"error checkSumsBalances !HexCheck(balanceAntL) "<<balanceAntL<<endl;
            exit_call();
        }
        
        balanceAntR = searchlastmoveCkBl2(bl2, accB,primer, last,  index);
        if( !HexCheck(balanceAntR) ){
            cout<<endl<<"error checkSumsBalances !HexCheck(balanceAntR) "<<balanceAntR<<endl;
            exit_call();
        }
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

    }

    balanceantl = hexToULL(balanceAntL.substr(0 ,16));
    balanceantr = hexToULL(balanceAntR.substr(0 ,16));


    if( DataTransac[0] == 0x04 ){     

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

        if(balanceantl<balanceL+ feed || balanceL+ feed < balanceL ){
                    cout<<endl<<" checksums DB Fail! 0004"<<endl;
            return false;
        } else { return true;}

    }

    if( DataTransac[0] == 0x06 ){

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

    if( DataTransac[0] == 0x08 ){     

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

    cout<<endl<<" account indexing algorithm init: "<<acctpubk<<endl;

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
        acctpubk= acctpubk.substr(2,128);
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
                cout<<endl<<"indexed acc in cache : "<<acctpubk;
                cout<<endl<<"value : "<<AccSync[acc].value<<endl;
                balance = ullToHex(AccSync[acc].value);
                mapIndex[acc].indexing = false;
                return balance;
            }
        }
    }

    auto iter  = AccSync.find(acc);
    if (iter != AccSync.end()){
        if(AccSync[acc].indexed){ 
            cout<<endl<<"indexed acc in cache : "<<endl;
            cout<<endl<<"value : "<<AccSync[acc].value<<endl;
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
                    cout<<endl<<"indexed acc in cache : "<<endl;
                    balance = ullToHex(mapIndex[acc].balance);
                    AccSync[acc].indexed = true;
                    mapIndex[acc].indexing = false;
                    return balance;
                
            }
            cout<<endl<<"acc indexed cached"<<endl;
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
            cout<<endl<<"mapIndex.size()>=accIndexMaxCache erasing last index free memory"<< endl;
            mapIndex.erase(key);
        }
    }

    mapIndex[acc].indexed = false;
    WritingAccSynclock.unlock();

    
// End Sync lock Section
////////////////////////////////////////////////////////////////////////////////////////////

    cout<<endl<<"Searching for a non-indexed account"<<endl;

    uint64_t last = lastBL;
    uint qttblks;
    uint64_t rests = 0;
    uint64_t sums = 0;
    vector<unsigned char> bl2;
    uint primerInit = 179;
    uint16_t compressPoint=0;
    bool AccIndexFound = false;
    uint16_t lastcompressPoint;
    vector<string> accB;

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

            cout<<endl<<"account found in the Block Head"<<endl;

            WritingAccSynclock.lock();
            
            if(Refactorizing|| lastBL !=lastbl){
                mapIndex[acc].indexing = false;
                return "refactorizing new block, try again in a few moments";
            }

            mapIndex[acc].balance = readAddressFeedBlBalance(bl2);
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

          //  cout<<endl<<"slm Block Read N "<< last<< " transac y["<< a <<"]"<<endl;


            uint8_t result = AccIndexCompare3(bl2,primerInit, last, acc, accB,compressPoint);

            //if acc is found on accRPoinr
            if (result == 2){

                //cout <<endl<<"slm search index result x: "<<last<<"y: "<<a<<" on AccRPoint" << endl;

                if(accB.size()<1){
                    cout<<endl<<"debug accB.size()<1";
                    exit_call();
                }
                unsigned char DataTransac[247];
                unsigned char signature[64];

				string datatransacstring="";
                string signaturestring="";
				
                buildTransacPointerFromBuffer(bl2,acc,primerInit,last, DataTransac);
                builSignaturePointerFromBuffer(bl2,primerInit,signature);

                //cout<<endl<<"writing data transac from pointer buffer return: "<<endl;
                for(int i =0;i<247;i++){
                    datatransacstring +=byteToHex2(DataTransac[i]);
                    //cout<<byteToHex(DataTransac[i]);
                }
                //cout<<endl<<"writing data signature: "<<endl;
                for(int i =0;i<64;i++){
                   // cout<<byteToHex(signature[i]);
                    signaturestring+=byteToHex2(signature[i]);
                }

                uint16_t accBsize = accB.size();
                uint16_t accNumberVector;
                for( accNumberVector= 0; accNumberVector< accBsize; accNumberVector++){

                    datatransacstring = datatransacstring.substr(0,2)+accB[accNumberVector].substr(0,128)+datatransacstring.substr(130,datatransacstring.length()-130);
                    for (auto &s : datatransacstring){s = toupper(s);}

                    //cout<<endl<<"data transac build "<<datatransacstring<<endl<<endl;

                    //verify if the signature match with the data transac and acc
                    if(!verifySignature(  datatransacstring, signaturestring, loadPublicKey(datatransacstring.substr(2,128) ))){
                        if(accNumberVector==accBsize-1){
                            accNumberVector++;
                            break;
                            cout<<endl<<"Error searchlastmove "+datatransacstring+" signature invalid "+signaturestring<<endl;
                            cout<<endl<<"error DB Corrupt!, False Signature"<<endl;
                            WritingAccSynclock.lock();
                            mapIndex[acc].indexing = false;
                            return "DB Corrupt!, Firm False";
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

                if(Refactorizing|| lastBL !=lastbl){
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

                if(accB.size()<1){
                    cout<<endl<<"debug accB.size()<1";
                    exit_call();
                }
                unsigned char DataTransac[247];
                unsigned char signature[64];

				string datatransacstring="";
                string signaturestring="";
				
                buildTransacPointerFromBuffer(bl2,acc,primerInit,last, DataTransac);
                builSignaturePointerFromBuffer(bl2,primerInit,signature);

                //cout<<endl<<"debug data transac: "<<endl;
                for(int i =0;i<247;i++){
                    datatransacstring +=byteToHex2(DataTransac[i]);
                    //cout<<byteToHex2(DataTransac[i]);
                }
                //cout<<endl<<"debug data signature: "<<endl;
                for(int i =0;i<64;i++){
                    //cout<<byteToHex2(signature[i]);
                    signaturestring+=byteToHex2(signature[i]);
                }

                uint16_t accBsize = accB.size();
                uint16_t accNumberVector;
                for( accNumberVector= 0; accNumberVector< accBsize; accNumberVector++){

                    datatransacstring = datatransacstring.substr(0,146)+accB[accNumberVector].substr(0,128)+datatransacstring.substr(274,datatransacstring.length()-274);
                    for (auto &s : datatransacstring){s = toupper(s);}

                    //cout<<endl<<"data transac debug "<<datatransacstring<<endl<<endl;

                    if(!verifySignature(  datatransacstring, signaturestring, loadPublicKey(datatransacstring.substr(2,128) ))){

                        if(accNumberVector==accBsize-1){
                            accNumberVector++;
                            break;
                            cout<<endl<<"invalid Firm"<<endl;
                            cout<<endl<<"error DB Corrupt!, Firm False"<<endl;
                            WritingAccSynclock.lock();
                            mapIndex[acc].indexing = false;
                            return "DB Corrupt!, Firm False";
                        }
                    }else {
                        cout<<endl<<"signature check success";
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

                if( DataTransac[0] == 4 || DataTransac[0] == 8){
                    if(readbalanceFromDatatransacArray(DataTransac, false)>readbalanceFromDatatransacArray(DataTransac, false)+BuildFeedOfTransacFromArray(DataTransac)+rests
                    || readbalanceFromDatatransacArray(DataTransac, false)>readbalanceFromDatatransacArray(DataTransac, false)+BuildFeedOfTransacFromArray(DataTransac)
                    ){

                        cout<<endl<<"Error slm overflow Side L -  acc: "<<acctpubk<<endl;
                        exit_call();

                    }
                    rests += readbalanceFromDatatransacArray(DataTransac, false)+BuildFeedOfTransacFromArray(DataTransac);
                    PrimerChange(bl2[primerInit],primerInit);
                    continue;
                }

                if(rests> readbalanceFromDatatransacArray(DataTransac, false)+sums){

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

    // cout<<endl<<"searchlastmove end alg 0 acc: "<<acctpubk<<endl;

    return balance;
}

string searchtransac(string hash){

    vector<unsigned char> bl2;
    uint16_t qttblks ;
    uint primer = 179;

    vector<string> accA;
    vector<string> accB;

    for(uint64_t blnmbr = lastbl; blnmbr>1; blnmbr--){
        blread2(to_string(blnmbr),bl2);
        primer = 179;
        qttblks = hexToULL(blkscontain2(bl2));
        for(uint16_t transacnmbr = qttblks; transacnmbr>=1;transacnmbr--){

            cout<<endl<<"debug fl"<<endl;

            accsvectorbuilder(bl2,blnmbr, primer,accA,accB);

            string transacstring = buildtransacString(accA, accB, bl2,primer, blnmbr);

            if(SHAstg(transacstring)==hash){
                return transacstring;
            }

            cout<< endl << transacstring << " "<< SHAstg(transacstring)<< endl;

            PrimerChange(bl2[primer],primer );
        }
    }

    return "Not Found in DB";

}



#endif
