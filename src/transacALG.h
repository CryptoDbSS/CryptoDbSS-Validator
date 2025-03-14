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

#ifndef TRANSACALG_H
#define TRANSACALG_H


#include "CryptoDbSS.cpp"

extern map<string,nodeStruct> Nodes;
extern vector<string> peersMatchMin;
extern mutex WritingAccSync;
vector<unsigned char> blRefactHashedQueryNode(string peerIpAddress);

extern bool matchminRounInit;
extern bool statusCheckRun;
extern bool comfirmOptrancasyncRun;
extern bool peersMatchMinBlock;
extern bool BlAntIsMatch;
extern map< array <unsigned char,64>, Accsync >AccSync;
extern map< array <unsigned char,64>, dbstruct >mapIndex;
extern map<string, string> queuetransacs;
extern uint16_t blksize;
extern uint16_t errorMatchminCount;
extern uint accIndexMaxCache;
extern int32_t pretransacpending;
extern int32_t transacsconfirmed;
extern uint64_t timingbl;
extern uint64_t Maxtimingbl;
extern int lastmatchsyncqueue;
extern uint queuReq;
extern uint64_t lastbl;
extern uint feeds_ratio;
extern const string idblockchainName;
extern mutex writingspace;
extern mutex blkQueuemtx;
extern mutex peerssyncblock;
extern mutex pricesingtransacCount;
extern mutex queuReqmtx;
extern mutex blRefactHashedBlockmtx;
extern mutex peersMatchMinBlockmtx;
extern vector<unsigned char> blRefactHashed;
extern vector<string> blksOPSyncQueue;
extern string F256;
extern time_t* transactime;
extern int transacmaxtime;
extern int32_t transacpendingcount;

extern string* blksOP;

bool Refactoring_internalSecu;
std::mutex mutex_Refactoring_internalSecu;

void exit_call();
string shaLBB();
void addHexStringInVector(vector<unsigned char> &vec, string datatocodify);
string searchlastmove(string acctpubk,bool IsAccSync);
bool FIRMCheck2(string sth, string blheaderdata);
array<unsigned char, 64> accArr(string acctpubk);
int maxblks();
string matchMinQueueIp();
string matchMinQueue();

bool IsTypeConfirmed(uint8_t bltype){

    return TransactionDataFormat[bltype].IsConfirmed;

}

uint8_t bltypeOfString(string &datatransaction){
    return hexToUint8_t(datatransaction.substr(0,2));
}

void BuilBLDataArray( vector<unsigned char> &blRefactHashedAnt ,vector<unsigned char>&blData, vector<unsigned char>&uncompressedbl ){

    extern string* blksOP;
    extern string ShaLBBBuffered;
    extern const string idBlckchn;
    extern string dir_feeds;
    extern int32_t transacsconfirmed;
    extern bool refactSHA;
    extern bool Refactorizing;

    uint64_t FeedSums = 0;
    std::unique_lock<std::mutex>writingspacelock(writingspace);

    for (int i = 0; i < maxblksize; i++){ // blocks builder
        if(IsTypeConfirmed(bltypeOfString(blksOP[i]))){
            if(FeedSums + hexToUint64(FeedOfTransac(blksOP[i])) >= FeedSums){
                FeedSums+=hexToUint64(FeedOfTransac(blksOP[i]));
            } else {
                cout<<endl<<"error refactvalidate() FeedSums + hexToUint(FeedOfTransac(blksOP[i])) > FeedSums"<<i <<" "<< FeedSums<<endl;
                //matchminRounInit = false;
                exit_call();
            }
        }
    }
    
    writingspacelock.unlock();

    //cout<<endl<<"debug feedsums refact "<<FeedSums<<endl;
    cout<<endl<<"Building HeadBl..."<<endl;
    //1
    addHexStringInVector(blData, shaLBB());
    addHexStringInVector(uncompressedbl, shaLBB());  
    //2
    addHexStringInVector(blData, "01");
    addHexStringInVector(uncompressedbl, "01");
    //3
    addHexStringInVector(blData, idBlckchn);
    addHexStringInVector(uncompressedbl, idBlckchn);
    //4
    addHexStringInVector(blData, SHAstg(matchMinQueue()));
    addHexStringInVector(uncompressedbl, SHAstg(matchMinQueue()));
    //5
    addHexStringInVector(blData, dir_feeds); // 9    -104-113
    addHexStringInVector(uncompressedbl, dir_feeds);
    //6
    addHexStringInVector(blData, ullToHex(hexToULL(searchlastmove(dir_feeds,false)) + FeedSums)); // 9
    addHexStringInVector(uncompressedbl, ullToHex(hexToULL(searchlastmove(dir_feeds,false)) + FeedSums));

    Refactorizing = true;

    addHexStringInVector(blData, ullToHex(lastbl + 1)); // id block
    addHexStringInVector(uncompressedbl, ullToHex(lastbl + 1));

    addHexStringInVector(blData, uint16ToHex(transacsconfirmed)); // quanti contain blocks
    addHexStringInVector(uncompressedbl, uint16ToHex(transacsconfirmed));

    if (blData.size() != 179 ){
        cout <<"Internal error refactvalidate() HeadBl build blData.size() != 179  "<<endl;
        exit_call();
    }

    writingspacelock.lock();

    for (uint16_t i = maxblksize; i > 0; i--){                          // blocks builder
        
        if(IsTypeConfirmed(bltypeOfString(blksOP[i-1]))){
            addHexStringInVector(uncompressedbl,blksOP[i-1]);
            addHexStringInVector(blData, compressTransac(blksOP[i-1],i-1));
        }
    }
    writingspacelock.unlock();

    addHexStringInVector(blData, "9696"); // end of blocks
    addHexStringInVector(uncompressedbl, "9696");


    std::unique_lock<std::mutex> blRefactHashedBlockmtxlock(blRefactHashedBlockmtx);

    blRefactHashedAnt=blRefactHashed;
    blRefactHashed.clear();

    blRefactHashed= sha3_256v(uncompressedbl);

    blRefactHashedBlockmtxlock.unlock();

    /*
    cout<<endl<<endl<<"refactvalidate uncompressed  bl: "<<endl;
    for(uint i = 0; i < uncompressedbl.size();i++){
        cout<<byteToHex2(uncompressedbl[i]);
    }

    cout<<endl<<endl;
    cout<<endl<<endl<<"bl refactvalidate is  : "<<endl;
    */
    for (uint8_t i = 0; i <blRefactHashed.size();i++){
        blData.push_back(blRefactHashed[i]);
        //cout<<byteToHex2(blRefactHashed[i]);
    }

}

bool ValidateBlockNetwork(vector<unsigned char> &blRefactHashedAnt){

    cout<<endl<<"Validating Block network..";

    while(time(nullptr)<timingbl+120){

        uint sums = 0;
        uint Discardsums = 0;
        std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
        auto Nodes2 = Nodes;

        peerssyncblocklock.unlock();

        auto it = Nodes2.begin();
        while (it != Nodes2.end()) {
            //cout<<endl<<"debug refact blRefactHashedQueryNode "<<it->second.ip<<endl;
            if(it->second.ip== "localhost" ){
                sums++;
                //cout<<endl<<"sums "<<sums<<endl;
                ++it;
                continue;
            }

            vector<unsigned char> result =  blRefactHashedQueryNode(it->second.ip);
            if( result == blRefactHashed){
                sums++;
                // cout<<endl<<"sums "<<sums<<endl;
            } else {
                if(result.size() == 32&&result!= blRefactHashedAnt ){
                    Discardsums++;
                    //cout<<endl<<"Discardsums "<<Discardsums<<endl;
                }else {
                //cout<<endl<<"refact validate skip bad response from node   "<<it->second.ip<<endl;
                }
            } 
            ++it;

        }
        if((sums*10000)/Nodes2.size() >= 5100 ) {
            cout<<endl<<"block : "<<lastblockbuilt()+1<<" Validate by: "<<sums<<"/"<<Nodes2.size();
            return true;
        }
        if((Discardsums*10000)/Nodes2.size() >= 5000 ) {

            cout<<endl<<"block rejected by network "<<Discardsums<<"/" <<Nodes2.size();
            
            std::unique_lock<std::mutex> blRefactHashedBlockmtxlock(blRefactHashedBlockmtx);
            blRefactHashed=blRefactHashedAnt;
            blRefactHashedBlockmtxlock.unlock();

            while (true){
                std::unique_lock<std::mutex> queuReqmtxlock(queuReqmtx);
                if (queuReq>0){
                    cout<<endl<<"refactvalidate()queuReq>0"; 
                    queuReqmtxlock.unlock();
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                break;
            }

            std::unique_lock<std::mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);

            if(peersMatchMin.size()>0){
                peersMatchMin.erase(peersMatchMin.begin() + 0);
            } 

            if(peersMatchMin.size()<1){
                matchminRounInit = false;
            } 

            peersMatchMinBlockmtxlock.unlock();

            std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);

            size_t blksOPSyncQueuesize= blksOPSyncQueue.size();
            if(BlAntIsMatch){
                for(int i = lastmatchsyncqueue; i<blksOPSyncQueuesize; i++ ){
                    blksOPSyncQueue.pop_back();
                }
            } else {
                blksOPSyncQueue.clear();
            }


            blkQueuemtxlock.unlock();

            std::unique_lock<std::mutex> WritingAccSynclock(WritingAccSync);
            AccSync.clear();
            WritingAccSynclock.unlock();
            
            return false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    cout<<endl<<"discar block timeout network "<<endl;
    std::unique_lock<std::mutex> blRefactHashedBlockmtxlock(blRefactHashedBlockmtx);
    blRefactHashed=blRefactHashedAnt;
    blRefactHashedBlockmtxlock.unlock();

    while (true){
        std::unique_lock<std::mutex> queuReqmtxlock(queuReqmtx);
        if (queuReq>0){
            cout<<endl<<"refactvalidate()queuReq>0"; 
            queuReqmtxlock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        break;
    }

    std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);
    size_t blksOPSyncQueuesize= blksOPSyncQueue.size();
    if(BlAntIsMatch){
        for(int i = lastmatchsyncqueue; i<blksOPSyncQueuesize; i++ ){
            blksOPSyncQueue.pop_back();
        }
    } else {
        blksOPSyncQueue.clear();
    }
    blkQueuemtxlock.unlock();
    std::unique_lock<std::mutex> WritingAccSynclock(WritingAccSync);
    AccSync.clear();
    WritingAccSynclock.unlock();
    matchminRounInit = false;
    return false;

}

string refactvalidate(){

    cout<<endl<<"refact validate alg init =====>";

    std::unique_lock<std::mutex> SecuRefactLock(mutex_Refactoring_internalSecu);

    if(Refactoring_internalSecu){
        return "";
    }

    Refactoring_internalSecu = true;

    SecuRefactLock.unlock();

    extern bool Refactorizing;
    extern bool postRefactRoundInit;
    extern string dir_feeds;
    extern bool syncqueue;
    extern vector<string> peersMatchMin;
    extern string publicDirNode;
    extern map<int, string> shablbbuffer;
    extern string LBBBuffered;
    extern string ShaLBBBuffered;
    extern const uint16_t maxblksize;
    extern uint queuReq;
    extern mutex WritingAccSync;
    extern vector<unsigned char> blRefactHashed;

    vector<unsigned char> byteArray;
    vector<unsigned char> uncompressedbl;
    vector<unsigned char> blRefactHashedAnt;
    
    BuilBLDataArray(blRefactHashedAnt, byteArray, uncompressedbl);

    if(!ValidateBlockNetwork(blRefactHashedAnt)){
        postRefactRoundInit = false;
        Refactorizing = false;
        Refactoring_internalSecu=false;
        return "the new block could not be validated";
    }

    errorMatchminCount = 0;

    postRefactRoundInit = false;
    
    std::unique_lock<std::mutex> WritingAccSynclock(WritingAccSync);

    while (comfirmOptrancasyncRun||syncqueue||statusCheckRun|| queuReq>0|| pretransacpending>0 ){ 
        cout<<endl<<"refactvalidate() loop: comfirmOptrancasyncRun||syncqueue||statusCheckRun"; 
        cout<<endl<<" "<<comfirmOptrancasyncRun<<" "<<syncqueue<<" "<<statusCheckRun<<" "<<queuReq<<" "<<pretransacpending;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    if(!saveNewBlock(byteArray)){
        cout<<"the new block cannot be storage"<<endl;
        exit_call();
    }

    for (auto const& x : AccSync){
        auto iter  = mapIndex.find(x.first);
        if (iter != mapIndex.end()){
            mapIndex[x.first].balance=x.second.value;
            mapIndex[x.first].DataCompressIndex=x.second.DataCompressIndex;
            mapIndex[x.first].indexed=true;
            mapIndex[x.first].indexing=false;

        }
    }
    for (auto const& x : mapIndex){
        if(mapIndex[x.first].DataCompressIndex<=maxCompPoint){
           mapIndex[x.first].DataCompressIndex++;
        }
    }
    array<unsigned char, 64 > DirFeedsReceiver = accArr(dir_feeds);
    mapIndex.erase(DirFeedsReceiver);

    WritingAccSynclock.unlock();


    ClearOpBlks();

    std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);

    if(BlAntIsMatch){

        cout<<endl<<"refact validate post BlAntIsMatch"<<endl;
        cout<<"BlAntIsMatch blksOPSyncQueue.size() "<<blksOPSyncQueue.size()<< endl;
        cout<<"BlAntIsMatch lastmatchsyncqueue "<<lastmatchsyncqueue<< endl;

        for(int i = 0 ; i<lastmatchsyncqueue; i++ ){
            blksOPSyncQueue.erase(blksOPSyncQueue.begin() + 0);
        }
    }

    if(matchMinQueueIp() == "localhost"){
        BlAntIsMatch = true;
        lastmatchsyncqueue = blksOPSyncQueue.size() ;
    }else {
        BlAntIsMatch = false;
        lastmatchsyncqueue = 0;
        blksOPSyncQueue.clear();
    }

    blkQueuemtxlock.unlock();

    LBBBuffered = blread(to_string(lastblockbuilt()));
    ShaLBBBuffered=shaLBB();

    std::unique_lock<std::mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);

    if(peersMatchMin.size()>0){
        peersMatchMin.erase(peersMatchMin.begin() + 0);
    }

    if(peersMatchMin.size() < 1 ){
        peersMatchMin.clear();
        matchminRounInit = false;
    }

    Refactorizing = false;
    Refactoring_internalSecu = false;
    cout<<endl<<"New Block "<< lastbl<< "validated and stored";
    DisplayAppInfo();
    return "ok";
}

void updateSumsAccPostTransaction(uint8_t &typetransaction, string &signedT, string &PublicSigner, string &PublicReceiver){

    std::unique_lock<std::mutex> WritingAccSynclock(WritingAccSync);
    uint64_t FeedsTransaction = FeedOfTransactionUint64(signedT);
    array <unsigned char,64> accarrL = accArr(PublicSigner);
            

    if(typetransaction == 0x00){

        array <unsigned char,64> accarrR = accArr(PublicReceiver);
        const uint64_t PreBalanceL = AccSync[accarrL].value;
        const uint64_t PreBalanceR = AccSync[accarrR].value;
        const uint64_t PostBalanceL = readbalanceuint64(signedT, false);
        const uint64_t PostBalanceR = readbalanceuint64(signedT, true);
        const uint64_t feed = hexToUint64(FeedOfTransac(signedT));

        if(PreBalanceL - (PostBalanceL+feed) != PostBalanceR - PreBalanceR || PreBalanceL - (PostBalanceL+feed) > PreBalanceL ||  
            PostBalanceL+feed< PostBalanceL || PostBalanceR - PostBalanceR>PostBalanceR ){

            cout<<endl<<"error internal badsums updateSumsAccPostTransaction() - Transaction "<< (PreBalanceL - (PostBalanceL+feed) != PostBalanceR - PreBalanceR)<<" "<<signedT<<endl;
            
            cout<<endl<< "PreBalanceL "<<PreBalanceL<<endl
            <<" PostBalanceL "<<PostBalanceL<<endl
            <<" feed "<<feed<<endl
            <<" PostBalanceR "<<PostBalanceR<<endl
            <<" PreBalanceR "<< PreBalanceR<<endl
            <<"operation "<< PreBalanceL - (PostBalanceL+feed)<< " "<< PostBalanceR - PreBalanceR<<endl;

            exit_call();

        }

        AccSync[accarrL].value = PostBalanceL;
        AccSync[accarrR].value = PostBalanceR;

        if( AccSync[accarrL].value != PostBalanceL || AccSync[accarrR].value != PostBalanceR ){

            cout<<endl<<"error updateSumsAccPostTransaction() AccSync[accarrL].value != readbalanceuint64(signedT, false) ||AccSync[accarrR].value != readbalanceuint64(signedT, true) - Transaction "<<signedT<<endl;
            exit_call();     

        }

    }

    if(typetransaction == 0x04){

        array <unsigned char,64> accarrR = accArr(PublicReceiver);
        const uint64_t PreBalanceL = AccSync[accarrL].value;
        const uint64_t PreBalanceR = AccSync[accarrR].value;
        const uint64_t sumsL = readbalanceuint64(signedT, false);
        const uint64_t sumsR = readbalanceuint64(signedT, true);
        const uint64_t feed = hexToUint64(FeedOfTransac(signedT));
        const uint64_t PostBalanceL = PreBalanceL - (sumsL+feed);
        const uint64_t PostBalanceR = PreBalanceR + sumsR;

        if( PreBalanceL - (sumsL+feed) > PreBalanceL || sumsL+feed < sumsL || PreBalanceR + sumsR <  PreBalanceR || sumsL != sumsR ){

            cout<<endl<<"error internal badsums updateSumsAccPostTransaction() - Transaction "<<signedT<<endl;
            exit_call();

        }

        AccSync[accarrL].value = PostBalanceL;
        AccSync[accarrR].value = PostBalanceR;

        if( AccSync[accarrL].value != PostBalanceL || AccSync[accarrR].value != PostBalanceR ){

            cout<<endl<<"error updateSumsAccPostTransaction() AccSync[accarrL].value != readbalanceuint64(signedT, false) ||AccSync[accarrR].value != readbalanceuint64(signedT, true) - Transaction "<<signedT<<endl;
            exit_call();     

        }

    }

    if(typetransaction == 0x06){

        array <unsigned char,64> accarrR = accArr(PublicReceiver);
        const uint64_t PreBalanceL = AccSync[accarrL].value;
        const uint64_t PreBalanceR = AccSync[accarrR].value;
        const uint64_t sumsR = readbalanceuint64(signedT, true);
        const uint64_t feed = hexToUint64(FeedOfTransac(signedT));
        const uint64_t PostBalanceL = readbalanceuint64(signedT, false);
        const uint64_t PostBalanceR = PreBalanceR + sumsR;

        if( PreBalanceL - (PostBalanceL+feed) != sumsR || PreBalanceL - (PostBalanceL+feed) > PreBalanceL || PostBalanceL+feed < PostBalanceL 
        || PreBalanceR + sumsR < PreBalanceR || PreBalanceR + sumsR != PostBalanceR ){

            cout<<endl<<"error internal badsums updateSumsAccPostTransaction() - Transaction "<<signedT<<endl;
            exit_call();

        }

        AccSync[accarrL].value = PostBalanceL;
        AccSync[accarrR].value = PostBalanceR;

        if( AccSync[accarrL].value != PostBalanceL || AccSync[accarrR].value != PostBalanceR ){

            cout<<endl<<"error updateSumsAccPostTr ansaction() AccSync[accarrL].value != readbalanceuint64(signedT, false) ||AccSync[accarrR].value != readbalanceuint64(signedT, true) - Transaction "<<signedT<<endl;
            exit_call();     

        }

    }

    if(typetransaction == 0x08){

        array <unsigned char,64> accarrR = accArr(PublicReceiver);
        const uint64_t PreBalanceL = AccSync[accarrL].value;
        const uint64_t PreBalanceR = AccSync[accarrR].value;
        const uint64_t sumsL = readbalanceuint64(signedT, false);
        const uint64_t feed = hexToUint64(FeedOfTransac(signedT));
        const uint64_t PostBalanceL = PreBalanceL-(sumsL+feed);
        const uint64_t PostBalanceR = readbalanceuint64(signedT, true);

        if( PreBalanceL - (sumsL+feed) > PreBalanceL || sumsL+feed < sumsL ||  PreBalanceL-(PostBalanceL+feed) != sumsL || PostBalanceR - PreBalanceR != sumsL || PostBalanceR - PreBalanceR > PostBalanceR ){

            cout<<endl<<"error internal badsums updateSumsAccPostTransaction() - Transaction "<<signedT<<endl;
            exit_call();

        }

        AccSync[accarrL].value = PostBalanceL;
        AccSync[accarrR].value = PostBalanceR;

        if( AccSync[accarrL].value != PostBalanceL || AccSync[accarrR].value != PostBalanceR ){

            cout<<endl<<"error updateSumsAccPostTr ansaction() AccSync[accarrL].value != readbalanceuint64(signedT, false) ||AccSync[accarrR].value != readbalanceuint64(signedT, true) - Transaction "<<signedT<<endl;
            exit_call();     

        }

    }

    if(typetransaction == 0x0A){

        const uint64_t PreBalanceL = AccSync[accarrL].value;
        const uint64_t PostBalanceL = readbalanceuint64(signedT, false);
        const uint64_t feed = hexToUint64(FeedOfTransac(signedT));

        if( PostBalanceL >  PreBalanceL || PreBalanceL-PostBalanceL != feed ){

            cout<<endl<<"error internal badsums updateSumsAccPostTransaction() - Transaction "<<signedT<<endl;

            cout<<endl<<"debug  "<< " PostBalanceL" <<to_string(PostBalanceL) <<" PreBalanceL" <<to_string(PreBalanceL) <<" feed " <<to_string(feed) <<endl;
            exit_call();

        }

        AccSync[accarrL].value = PostBalanceL; 

        if( AccSync[accarrL].value != PostBalanceL){

            cout<<endl<<"error updateSumsAccPostTransaction() AccSync[accarrL].value != readbalanceuint64(signedT, false) ||AccSync[accarrR].value != readbalanceuint64(signedT, true) - Transaction "<<signedT<<endl;
            exit_call();     

        }
    }

    if(typetransaction == 0x0C){

        const uint64_t PreBalanceL = AccSync[accarrL].value;
        const uint64_t feed = hexToUint64(FeedOfTransac(signedT));
        const uint64_t PostBalanceL = PreBalanceL - feed;

        if( feed >  PreBalanceL || PreBalanceL-feed > PreBalanceL){

            cout<<endl<<"error internal badsums updateSumsAccPostTransaction() - Transaction "<<signedT<<endl;
            exit_call();

        }

        AccSync[accarrL].value = PostBalanceL; 

        if( AccSync[accarrL].value != PostBalanceL){

            cout<<endl<<"error updateSumsAccPostTr ansaction() AccSync[accarrL].value != readbalanceuint64(signedT, false) ||AccSync[accarrR].value != readbalanceuint64(signedT, true) - Transaction "<<signedT<<endl;
            exit_call();     

        }
    }

    
    WritingAccSynclock.unlock();


}

bool preTransacAsync0x0AOp2_3_5_7_9_11(string &accL, string &accBlL, string &accR, string &accBlR, string &queuetransac,  uint8_t &PreTransacType, uint8_t &OpTransacType, uint64_t &feeds, uint &blkSpace ,  uint64_t &rests, uint64_t &balanceL, uint64_t &balanceR ){

    //2 9

    if ( OpTransacType == 2 || OpTransacType == 9 ){

        if(accL == accBlL){
            rests =  balanceL;
        } else if(accL == accBlR) {
            rests =  balanceR;
        } else { 
            cout<<endl<<" error in  preTransacAsync0x0AOp2_3_5_7_9_11"<<endl;
            exit_call();
            return false;
        }
        
    }

    //3 7 11

    if (OpTransacType == 3|| OpTransacType == 7 || OpTransacType == 11 ){

        if(  rests - (balanceL+feeds)  >= rests || balanceL+feeds < balanceL ){ 
            cout<<endl<<"bad sums acc transacs";
            blksOP[blkSpace]= F256+F256;    
            cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
            queuetransacs[queuetransac] = "bad sums";
            return false;    
        }

        rests-=balanceL+feeds; // colocar solo si es accl

    }

    //5

    if(OpTransacType == 5 ){
        if(accL == accBlL){
            rests =  balanceL;
        } 
    }
    
    PreTransacType = 11;

    return true;

}

bool preTransacAsync0x00Op9_11(string &accL, string &accBlL, string &accR, string &accBlR, string &queuetransac,  uint8_t &PreTransacType, uint8_t &OpTransacType, uint64_t &feeds, uint &blkSpace ,  uint64_t &rests, uint64_t &balanceL, uint64_t &balanceR ){
	
	if(accL== accBlL){
		
		if(OpTransacType == 0x09){
			
			rests =  balanceL;
			PreTransacType = 7;
			
		} else if(OpTransacType == 0x11){
			
			if(  rests - (balanceL+feeds)  >= rests || balanceL+feeds < balanceL ){ 
                    cout<<endl<<"bad sums acc transacs";
                    blksOP[blkSpace]= F256+F256;    
                    cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                    queuetransacs[queuetransac] = "bad sums";
                    return false;    
                }
            rests-=balanceL+feeds;
         } else{
			cout<<endl<<" error in  preTransacAsync0x00Op9_11"<<endl;
            exit_call();
            return false;
		} 
	}
		
	if(accR == accBlL){
		PreTransacType = 5;
	}
	
	if(PreTransacType != 5 && PreTransacType != 7 ){
		return false;
	}
	
	return true;
	
}

bool preTransacAsync0x00Op2_3_5_7(string &accL, string &accBlL, string &accR, string &accBlR, string &queuetransac,  uint8_t &PreTransacType, uint8_t &OpTransacType, uint64_t &feeds, uint &blkSpace ,  uint64_t &rests, uint64_t &balanceL, uint64_t &balanceR ){

        //pre defining 03
    if ((accL == accBlL && accR == accBlR) || (accL == accBlR && accR == accBlL)){  

        PreTransacType = 3;

        if(OpTransacType  == 2 ){
            //cout<<endl<<"OpTransacType  == 2 "<< balanceL<<" "<<balanceR;
            if(accL == accBlL){
                rests =  balanceL;
            } else {
                rests =  balanceR;
            }
        }

        if(OpTransacType  == 3 ){

            if(accL == accBlL){
            
                if(  rests - (balanceL+feeds)  >= rests || balanceL+feeds < balanceL ){ 
                    cout<<endl<<"bad sums acc transacs";
                    blksOP[blkSpace]= F256+F256;    
                    cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                    queuetransacs[queuetransac] = "bad sums";
                    return false;    
                }

                rests-=balanceL+feeds; // colocar solo si es accl
            } 

        }

        if(OpTransacType == 5  ){

            if(accL == accBlL){
                rests =  balanceL;
            } 
        }

        if(OpTransacType  == 7 ){
            if(accL == accBlL){
                if(  rests - (balanceL+feeds)  >=rests || balanceL+feeds < balanceL ){ 
                    cout<<endl<<"bad sums acc transacs";
                    blksOP[blkSpace]= F256+F256;    
                    cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                    queuetransacs[queuetransac] = "bad sums";
                    return false;    
                }
                rests-=balanceL+feeds; // anadir feed

            } else {
                rests =  balanceR;
            }                                                                                                                                                                                       
        }

        //cout<<endl<<"now PreTransacType is "<<byteToHex2(PreTransacType)<<endl;
    }
        //pre defining 05
    if (PreTransacType != 3 && (accL != accBlL||accL != accBlR) && (accR == accBlL||accR == accBlR)){
        PreTransacType = 5;
        //cout<<endl<<"PreTransacType is now "<<PreTransacType<<endl;
    }    
        //pre defining 07
    if (PreTransacType != 3 &&(accL == accBlL||accL ==accBlR)&& (accR != accBlL||accR != accBlR)){

        if(OpTransacType  == 2 ){
            if(accL == accBlL){
                rests =  balanceL;
            } else {
                rests =  balanceR;
            }
        }

        if(OpTransacType  == 3 ){

            if(accL == accBlL){
            
                if(  rests - (balanceL+feeds)  >=rests || balanceL+feeds < balanceL ){ 
                    cout<<endl<<"bad sums acc transacs";
                    blksOP[blkSpace]= F256+F256;    
                    cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                    queuetransacs[queuetransac] = "bad sums";
                    return false;
                }

                rests-=balanceL+feeds;
            } 


        }

        if(OpTransacType  == 5  ){
            if(accL == accBlL){
                rests =  balanceL;
            } 
        }

        if(OpTransacType  == 7 ){
            if(accL == accBlL){
                if(  rests - (balanceL+feeds)  >=rests || balanceL+feeds < balanceL ){ 
                    cout<<endl<<"bad sums acc transacs";
                    blksOP[blkSpace]= F256+F256;    
                    cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                    queuetransacs[queuetransac] = "bad sums";
                    return false;    
                }

                rests-=balanceL+feeds; // colocar solo si es accl
            } else {

                rests =  balanceR;
            }

        }

        PreTransacType = 7;

        //cout<<endl<<"now PreTransacType is  "<<PreTransacType<<endl;
    }
        //throuht error
    if (PreTransacType != 3 &&PreTransacType != 5&&PreTransacType != 7){
        cout<<endl<<"preTransacAsync0x00Op2_3_5_7 internal trouble in type of transac OpTransacType not match  - bl @ : "<< blksOP[blkSpace]<<endl;

        blksOP[blkSpace]= F256+F256;      

        queuetransacs[queuetransac] = "internal server trouble PreTransacType != bltype";
        exit_call();
        return false;   

    }

    cout<<endl<<"wobuchilada "<<to_string(PreTransacType);

    return true;
}

bool preDefineAsyncTransacType(string &accL, string &accBlL, string &accR, string &accBlR, string &queuetransac, uint8_t &transactionTypeReq,  uint8_t &PreTransacType, uint8_t &OpTransacType, uint64_t &feeds, uint &blkSpace, uint64_t &rests, uint64_t &balanceL, uint64_t &balanceR  ){

    switch(transactionTypeReq){

        case 0x00:

			switch(OpTransacType){
				
				case 0x02:
				case 0x03:
				case 0x05:
				case 0x07:
				
					return preTransacAsync0x00Op2_3_5_7(accL, accBlL, accR, accBlR, queuetransac, PreTransacType, OpTransacType, feeds, blkSpace, rests, balanceL, balanceR);
					break;
				
				case 0x09:
				case 0x11:
				
					return preTransacAsync0x00Op9_11(accL, accBlL, accR, accBlR, queuetransac, PreTransacType, OpTransacType, feeds, blkSpace, rests, balanceL, balanceR);
					break;
					
				default:
				
					cout<<endl<<" error in  preDefineAsyncTransacType switch(OpTransacType) no match"<<endl;
                    exit_call();
                    return false;
				
			}
            
            break;

        case 0x0A:
        case 0x0C:

            return preTransacAsync0x0AOp2_3_5_7_9_11(accL, accBlL, accR, accBlR, queuetransac,  PreTransacType, OpTransacType, feeds, blkSpace ,  rests, balanceL, balanceR);

            break;

        default:
        
            cout<<endl<<" error in  preDefineAsyncTransacType switch(transactionTypeReq) no match"<<endl;
            exit_call();
            return false;
        
    }
} 

bool preDatalengthIsValid(string &DataTransaction){

    return DataTransaction.length() == TransactionDataFormat[hexToUint8_t(DataTransaction.substr(0,2))].POS_signatureWithHidden_string;

}

bool DataTransactionlengthIsValid(string &DataTransaction){

    return TransactionDataFormat[hexToUint8_t(DataTransaction.substr(0 , 2))].size_fullTransaction_String == DataTransaction.length();

}

string DataTransacWithoutSignature(string &DataTransaction){

    return DataTransaction.substr(0, TransactionDataFormat[bltypeOfString(DataTransaction)].POS_signatureWithHidden_string) ;

}

bool checkTransactionsBuildLogic(uint8_t &OpTransacType , uint8_t &PreTransacType, string &accL, string &accR, string &accBlL, string &accBlR){

    if( ( accL == accBlL ) && (!TransactionDataFormat[PreTransacType].ValLIsDef) && ( TransactionDataFormat[OpTransacType].ValLIsDef ) ){
        cout<<endl<<" !checkTransactionsBuildLogic - accL == accBlL";
        return false;    
    }
    if( ( accL == accBlR ) && (!TransactionDataFormat[PreTransacType].ValLIsDef) && (TransactionDataFormat[OpTransacType].ValRIsDef) ){
        cout<<endl<<" !checkTransactionsBuildLogic - accL == accBlR";
        return false;      
    }
    if( ( accR == accBlL ) && (!TransactionDataFormat[PreTransacType].ValRIsDef) && ( TransactionDataFormat[OpTransacType].ValLIsDef )){
        cout<<endl<<" !checkTransactionsBuildLogic - accR == accBlL";
        return false;     
    }
    if( ( accR == accBlR ) && (!TransactionDataFormat[PreTransacType].ValRIsDef) && ( TransactionDataFormat[OpTransacType].ValRIsDef )){
        cout<<endl<<" !checkTransactionsBuildLogic -  accR == accBlR";
        return false;    
    }
    return true;
}

bool isAcclock(uint8_t &OpTransacType , string &accL, string &accR, string &accBlL, string &accBlR){

    if( (OpTransacType == 2||OpTransacType == 3||OpTransacType == 5||OpTransacType == 7|| OpTransacType == 9 || OpTransacType == 11) && (accL == accBlL||accR == accBlR|| accR == accBlL||accL == accBlR) ){
        return true;
    }
    return false;
}

void processAsyncTransac(string queuetransac, string stg1, uint8_t &transactionTypeReq, uint64_t value ){

    if (!preDatalengthIsValid( stg1)) {

        cout<<endl<<"getDataTransac error !length : "<<stg1.length()<<"   "<<stg1<<endl;
        cout<<endl<<"debug transactionTypeReq"<<uintToHex(transactionTypeReq)<<endl;
        queuetransacs[queuetransac] = "DataTransac error !length : "+ stg1;
        return;

    }
    
    std::unique_lock<std::mutex> writingspacelock(writingspace);
    
    vector<unsigned char> vec;
    addHexStringInVector(vec, stg1);
    uint8_t PreTransacType =hexToUint8_t(stg1.substr(0,2));
    uint blkSpace = WriteSpaceOp (vec);
    blksOP[blkSpace] = stg1;
    string accL = readaccountString(stg1, false);
    string accR = "";

    if(PreTransacType == 0x02){
        accR = readaccountString(stg1, true);
    }
    
    uint64_t rests;
    uint8_t OpTransacType;
    string accBlL;
    string accBlR;
    uint64_t balanceL;
    uint64_t balanceR;

    rests =  hexToULL(readbalanceString(stg1 , false ));

    for(int i = 0; i< blkSpace ;i++){

        OpTransacType = typebl2(blksOP[i]);
        if( OpTransacType == 0xFF ){ continue;}
        accBlL = readaccountString(blksOP[i] , false );
        accBlR = readaccountString(blksOP[i] , true );
        balanceL = readbalanceuint64(blksOP[i] , false);
        balanceR = readbalanceuint64(blksOP[i] , true);
        uint64_t feeds = hexToUint(FeedOfTransac(blksOP[i]));

        if ( isAcclock(OpTransacType,accL, accR, accBlL, accBlR ) ){

            if(preDefineAsyncTransacType( accL, accBlL, accR, accBlR, queuetransac, transactionTypeReq,  PreTransacType, OpTransacType, feeds, blkSpace, rests, balanceL, balanceR)){
                    
                i++;

                for(i; i<blkSpace ;i++){

                    OpTransacType = typebl2(blksOP[i]);
                    if( OpTransacType == 0xFF ){ continue;}
                    accBlL = readaccountString(blksOP[i] , false );
                    accBlR = readaccountString(blksOP[i] , true );
                    balanceL = readbalanceuint64(blksOP[i] , false);
                    balanceR = readbalanceuint64(blksOP[i] , true);

                    if ((accL== accBlL || accL == accBlR)&& PreTransacType == 5 && (OpTransacType == 2 ||OpTransacType == 3 ||OpTransacType == 5 ||OpTransacType == 7 ||OpTransacType == 9 ||OpTransacType == 11)){
                        PreTransacType = 3;
                    }

                    if ((accR== accBlL|| accR == accBlR)&& PreTransacType == 7 && (OpTransacType == 2||OpTransacType == 3||OpTransacType == 5||OpTransacType == 7||OpTransacType == 9 ||OpTransacType == 11)){
                        PreTransacType = 3;
                    }

                    if(!checkTransactionsBuildLogic(OpTransacType, PreTransacType, accL, accR, accBlL, accBlR)){
                        cout<<endl<<" !checkTransactionsBuildLogic - bl @"<<i <<" : "<< blksOP[i]<<endl;
                        cout<<endl<<"debug blkSpace "<<blkSpace<<" OpTransacType "<<uintToHex(OpTransacType) <<" PreTransacType "<< uintToHex(PreTransacType)<<endl;
                        exit_call();
                    }


                    if ( accL == accBlL && (OpTransacType == 3||OpTransacType == 4||OpTransacType == 7||OpTransacType == 8) ){

                            if(  rests - (balanceL+feeds)  >=rests || balanceL+feeds < balanceL ){ 
                                cout<<endl<<"bad sums acc";
                                blksOP[blkSpace]= F256+F256;    
                                cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                                queuetransacs[queuetransac] = "bad sums";
                                return;    
                            }
                            rests-=balanceL+feeds; // colocar solo si es accl
                    }

                    if ( accL == accBlL && OpTransacType == 11 ){

                            if(  rests - balanceL  >=rests  ){ 
                                cout<<endl<<"bad sums acc";
                                blksOP[blkSpace]= F256+F256;    
                                cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                                queuetransacs[queuetransac] = "bad sums";
                                return;    
                            }

                            rests-=balanceL; // colocar solo si es accl

                    }

                    if ( (accL == accBlR)&&(OpTransacType == 4||OpTransacType == 6) ){
                        if( rests + balanceR <= rests ){ 
                            cout<<endl<<"bad sums acc transacs";
                            blksOP[blkSpace]= F256+F256;    
                            cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                            queuetransacs[queuetransac] = "bad sums";
                            return;    
                        }
                        rests += balanceR;
                    }  
                }
                //cout <<endl<<"debug rests "<< rests<<endl;
            } else{
                cout<<" !preDefineAsyncTransacType "<<endl;
                exit_call();
            }            
        }
    }

    if( PreTransacType == 3 ||PreTransacType == 7 ||OpTransacType == 11){
        if(rests <value+ hexToUint(FeedOfTransac(stg1)) || value+ hexToUint(FeedOfTransac(stg1)) < value){
            cout<<endl<<"sums error rests <1 && (PreTransacType == 03 ||PreTransacType == 07) - rests "<<rests<<endl;
            blksOP[blkSpace]= F256+F256;    
            queuetransacs[queuetransac] = "bad sums";
            return;
        }
    }

    if(blksOP[blkSpace] == stg1 ){

        changeBlNmbr(stg1, uintToHex(blkSpace+1).substr(4,4));

        if(PreTransacType == 3||PreTransacType == 5||PreTransacType == 7||PreTransacType == 11){
            cout<<endl<<"PreTransacType pre "<<PreTransacType<<endl;
            //cout<<endl<<"debug stg pre change "<< stg1<<" length "<<stg1.length()<<endl;
            if(!changeBlType(stg1,uintToHex(PreTransacType).substr(6,2), value)){
                cout<<endl<<"error getdatatransacthread1() !changeBlType(stg1,uintToHex(PreTransacType).substr(6,2), value)"<<endl;
                exit_call();
            }
            //cout<<endl<<"debug stg post change "<< stg1<<" length "<<stg1.length()<<endl;
            cout<<endl<<"PreTransacType post"<< typebl(stg1) <<endl;
        }

        for (auto &c:stg1){c=toupper(c);}

        blksOP[blkSpace] = stg1;

        std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);
        blksOPSyncQueue.push_back( uintToHex(blkSpace)+stg1.substr(0, 302));
        blkQueuemtxlock.unlock();
                                        
        if(typebl(stg1) == "02" ||  typebl(stg1) == "03"|| typebl(stg1) == "05" || typebl(stg1) == "07"|| typebl(stg1) == "09"|| typebl(stg1) == "0B"){
            stg1 = switchBlType(stg1);
        }
    
        queuetransacs[queuetransac] =  stg1;
        //cout<<endl<<"data transac i space "<<blkSpace<<endl;
        //cout<<endl<<"data transac res body "<<res.body<<endl;
        transactime[blkSpace] = time(nullptr)+transacmaxtime;

        //verificar que la data sea correcta

        //cout<<endl<<"   <===   GetDataTransac end thread 0"<<endl;

        //sumar transacpendingcount
        std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);
        transacpendingcount++;
        return;                                                 
    }

    blksOP[blkSpace]= F256+F256;

    cout<<endl<<"error no se encontro el espacio de la transaccion en la memoria"<<endl<<blksOP[blkSpace];
    queuetransacs[queuetransac] = "handle error writing memory";
    exit_call();

    return;

}

string DataTransac0x0A(string &DataTransacJson){

    extern const string idBlckchn;
    extern string ShaLBBBuffered;

    auto x = crow::json::load(DataTransacJson);

    string From = x["w"].s();
    string Msg32 = x["x"].s();
    string cantS = x["y"].s();
    uint64_t cant = hexToUint64(cantS);

    if (From.length() != 130 || Msg32.length() != 64){ return "Invalid address";}
    /*
    if (!HexCheck(From) || !HexCheck(Msg32)||!HexCheck(cantS) ){ 
        return "Invalid_Characters";
    }
    */
    if(cant<1){return "value transac < 0";}
    for (auto &s : From){ s = toupper(s);}
    for (auto &s : Msg32){ s = toupper(s);}

    // indexing of sender
    string verifier_index =searchlastmove( From,true);

    if (!HexCheck(verifier_index)){
        cout<<endl<<"DataTransac error !HexCheck(verifier_index) ";
        return verifier_index;
    }

    uint64_t value = hexToULL(verifier_index);

    if (value < cant){
        return "The account does not have the required balance to process the transaction. balance: " + to_string(value);
    }
 
    uint64_t rest = value - cant;

    vector<unsigned char> byteArray;

    string blckheader = shaLBB();
    string ShaMin = matchMinQueue();
    for (auto &s : ShaMin){s = toupper(s);}
    string hidden =idBlckchn+blckheader+ SHAstg(ShaMin);

    addHexStringInVector(byteArray, "09"); //2
    addHexStringInVector(byteArray, "0000");//2
    addHexStringInVector(byteArray, From.substr(2,128));//65
    addHexStringInVector(byteArray, uint64ToHex(rest));//8
    addHexStringInVector(byteArray, uint64ToHex(cant));//8
    addHexStringInVector(byteArray, Msg32);
    addHexStringInVector(byteArray, hidden);

    // hidden

    string data = vectorstring(byteArray);
    for (auto &s : data){ s = toupper(s); }

    return data;

}

string DataTransac0x00(string &DataTransacJson){

    extern const string idBlckchn;
    extern string ShaLBBBuffered;

    auto x = crow::json::load(DataTransacJson);

    string TransactionType = x["v"].s();
    string From = x["w"].s();
    string to = x["x"].s();
    string cantS = x["y"].s();
    uint64_t cant = hexToUint64(cantS);

    if (From.length() != 130 || to.length() != 130){ return "Invalid address";}
    if (to.substr(0, 2) != "04" || From.substr(0, 2) != "04"){return "Invalid address";}
    if (!HexCheck(From) || !HexCheck(to)||!HexCheck(cantS)){return "Invalid_Characters";}
    if (From == to) {return "same addresses";}
    if(cant<1){return "value transac < 0";}
    for (auto &s : From){ s = toupper(s);}
    for (auto &s : to){ s = toupper(s);}

    // indexing of sender
    string verifier_index =searchlastmove( From,true);

    if (!HexCheck(verifier_index)){
        cout<<endl<<"DataTransac error !HexCheck(verifier_index) ";
        return verifier_index;
    }

    uint64_t value = hexToULL(verifier_index);
    uint feed = percent(cant, feeds_ratio);

    if(feed>value||feed>cant){
        cout<<endl<<"error desdoblado de buffer"<<endl;
        cout<<"cant "<<cant<<" value: "<<value<<" feed: "<<feed<<endl;
        return "error desdoblado de buffer";
    }
    if (value-feed < cant){
        return "value-feed < cant - balance insuficiente, saldo actual: " + to_string(value);
    }
 
    uint64_t rest = (value - cant) - feed;


    // indexing of receiver
    verifier_index =searchlastmove( to,true);

    if (!HexCheck(verifier_index)){
        cout<<endl<<"DataTransac error !HexCheck(verifier_index) ";
        return verifier_index;
    }

    uint64_t sum = cant + hexToULL(verifier_index);

    vector<unsigned char> byteArray;

    string blckheader = shaLBB();

    addHexStringInVector(byteArray, "02"); //2
    addHexStringInVector(byteArray, From.substr(2,128));//65
    addHexStringInVector(byteArray, ullToHex(rest));//8
    addHexStringInVector(byteArray, to.substr(2,128));//65
    addHexStringInVector(byteArray, ullToHex(sum));//8
    addHexStringInVector(byteArray, "0000");//2
    addHexStringInVector(byteArray, intToHex(feed)); //4

    // hidden

    string ShaMin = matchMinQueue();
    for (auto &s : ShaMin){s = toupper(s);}
    ShaMin = SHAstg(ShaMin);

    string hidden =idBlckchn+blckheader+ ShaMin;
    addHexStringInVector(byteArray, hidden); 
    string data = vectorstring(byteArray);
    for (auto &s : data){ s = toupper(s); }

    return data;

}

string GetDataTransac(string &DataTransacJson, uint8_t &TransactionType){

    string datatransac = "";

    if(TransactionType == 0x00 ){

       datatransac = DataTransac0x00(DataTransacJson);

    }

    if(TransactionType == 0x0A ){

        datatransac = DataTransac0x0A(DataTransacJson);

    }

    if(datatransac.length() == 0 ){
        return "error";
    }

    return datatransac;

}

string SignedTransac0002(string signedT){

    extern map< array <unsigned char,64>, dbstruct>mapIndex;
    extern mutex writingspace;
    extern int32_t transacpendingcount;
    extern const string idBlckchn;
    extern string publicDirNode;
    extern string *blksOP;
    extern map<int, string> shablbbuffer;
    extern string LBBBuffered;
    extern string ShaLBBBuffered;

    for (auto &s : signedT){s = toupper(s);}

    uint8_t typetransac = hexToUint8_t(signedT.substr(0,2));
    string PublicSigner = readaccountString(signedT, false);
    string PublicReceiver = readaccountString(signedT, true);
    string blcknmbr = blOpNmbr(signedT);
    string ShaMin = matchMinQueue();

    for (auto &s : ShaMin){s = toupper(s);}
    ShaMin=SHAstg(ShaMin);
    for (auto &s : ShaMin){s = toupper(s);}

    string datatransacString = readDataTransac( signedT);
    string datatransacStringShort = datatransacString.substr(0, TransactionDataFormat[typetransac].POS_hidden_string);
    string SignatureTransaction = signedT.substr(TransactionDataFormat[typetransac].POS_signatureWithHidden_string, 128);

    if (verifySignature(datatransacString, SignatureTransaction, loadPublicKey(PublicSigner))  ){
        if (FIRMCheck2(datatransacStringShort + SignatureTransaction, idBlckchn + shaLBB() + ShaMin)){

            vector<unsigned char> byteArray;
            addHexStringInVector(byteArray, datatransacStringShort + SignatureTransaction);
            string datafromArr = vectorstring(byteArray);
            for (auto &s : datafromArr){s = toupper(s);}

            std::unique_lock<std::mutex> writingspacelock(writingspace);

            if(switchBlType(blksOP[ hexToInt(blOpNmbr(signedT))-1])!= datatransacString){
                std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);
                transacpendingcount--;
                return "error signed transac blksOP[ hexToInt(blOpNmbr(signedT))]!= datatransacString";
            }

            blksOP[hexToInt(blcknmbr)-1] = datatransacStringShort + SignatureTransaction;
            writingspacelock.unlock();

            updateSumsAccPostTransaction( typetransac, datatransacStringShort, PublicSigner, PublicReceiver);

            std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);
            transacsconfirmed++;
            pricesingtransacCountlock.unlock();
            
            extern string dir_feeds;

            if ( matchMinQueueIp() == "localhost"){
                std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);
                blksOPSyncQueue.push_back(intToHex(hexToInt(blOpNmbr(signedT))-1)+datatransacStringShort+SignatureTransaction );
                blkQueuemtxlock.unlock();
            }

            pricesingtransacCountlock.lock();
            transacpendingcount--;
            pricesingtransacCountlock.unlock();

            if (transacsconfirmed > blksize){
                cout<<endl<<"error refactvalidate transacsconfirmed > blksize"<<endl;
                exit_call();
            }

            return "SUCCESS - Block: " + datatransacStringShort + SignatureTransaction;
        } 
    }


    std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);
    transacpendingcount--;
    return "FAIL VERIFICATION: " + signedT;
}

#endif

