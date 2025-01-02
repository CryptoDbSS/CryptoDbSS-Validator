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
extern uint16_t blksize;
extern uint16_t errorMatchminCount;
extern uint accIndexMaxCache;
extern int32_t pretransacpending;
extern int32_t transacscomfirmed;
extern uint64_t timingbl;
extern uint64_t Maxtimingbl;
extern int lastmatchsyncqueue;
extern uint queuReq;
extern uint64_t lastbl;
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

void exit_call();
string shaLBB();
void addHexStringInVector(vector<unsigned char> &vec, string datatocodify);
string searchlastmove(string acctpubk,bool IsAccSync);
bool FIRMCheck2(string sth, string blheaderdata);
array<unsigned char, 64> accArr(string acctpubk);
int maxblks();
string matchMinQueueIp();
string matchMinQueue();

void BuilBLDataArray( vector<unsigned char> &blRefactHashedAnt ,vector<unsigned char>&blData, vector<unsigned char>&uncompressedbl ){

    extern string* blksOP;
    extern string ShaLBBBuffered;
    extern const string idBlckchn;
    extern string dir_feeds;
    extern int32_t transacscomfirmed;
    extern bool refactSHA;
    extern bool Refactorizing;

    uint FeedSums = 0;
    std::unique_lock<std::mutex>writingspacelock(writingspace);

    for (int i = 0; i < maxblksize; i++){ // blocks builder
        if(typebl(blksOP[i]) == "00" || typebl(blksOP[i]) == "04" || typebl(blksOP[i]) == "06"|| typebl(blksOP[i]) == "08"){
            if(FeedSums + hexToUint(FeedOfTransac(blksOP[i])) >= FeedSums){
                FeedSums+=hexToUint(FeedOfTransac(blksOP[i]));
            } else {
                cout<<endl<<"error refactvalidate() FeedSums + hexToUint(FeedOfTransac(blksOP[i])) > FeedSums"<<i <<" "<< FeedSums<<endl;
                //matchminRounInit = false;
                exit_call();
            }
        }
    }
    
    writingspacelock.unlock();

    cout<<endl<<"debug feedsums refact "<<FeedSums<<endl;
    cout<<endl<<"Building HeadBl..."<<endl;
    //1
    addHexStringInVector(blData, shaLBB());
    addHexStringInVector(uncompressedbl, shaLBB());  
    cout << endl<< "1 " << blData.size();
    //2
    addHexStringInVector(blData, "01");
    addHexStringInVector(uncompressedbl, "01");
    cout << endl<< "2 " << blData.size();
    //3
    addHexStringInVector(blData, idBlckchn);
    addHexStringInVector(uncompressedbl, idBlckchn);
    cout << endl<< "3 " << blData.size();
    //4
    addHexStringInVector(blData, SHAstg(matchMinQueue()));
    addHexStringInVector(uncompressedbl, SHAstg(matchMinQueue()));
    cout << endl<< "4 " << blData.size();
    //5
    addHexStringInVector(blData, dir_feeds); // 9    -104-113
    addHexStringInVector(uncompressedbl, dir_feeds);
    cout << endl<< "5 " << blData.size();
    //6
    addHexStringInVector(blData, ullToHex(hexToULL(searchlastmove(dir_feeds,false)) + FeedSums)); // 9
    addHexStringInVector(uncompressedbl, ullToHex(hexToULL(searchlastmove(dir_feeds,false)) + FeedSums));
    cout << endl<< "6 " << blData.size();

    Refactorizing = true;

    addHexStringInVector(blData, ullToHex(lastbl + 1)); // id block
    addHexStringInVector(uncompressedbl, ullToHex(lastbl + 1));
    cout << endl<< "7 " << blData.size();

    addHexStringInVector(blData, uint16ToHex(transacscomfirmed)); // quanti contain blocks
    addHexStringInVector(uncompressedbl, uint16ToHex(transacscomfirmed));
    cout << endl<< "8 " << blData.size();

    cout << endl<< "size pre 9696 id " << blData.size();

    if (blData.size() != 179 ){
        cout <<"Internal error refactvalidate() HeadBl build blData.size() != 179  "<<endl;
        exit_call();
    }

    writingspacelock.lock();

    for (uint16_t i = maxblksize; i > 0; i--){                          // blocks builder
        
        if(typebl(blksOP[i-1]) == "00" || typebl(blksOP[i-1]) == "04" || typebl(blksOP[i-1]) == "06"|| typebl(blksOP[i-1]) == "08"){
            addHexStringInVector(uncompressedbl,blksOP[i-1]);
            addHexStringInVector(blData, compressTransac(blksOP[i-1],i-1));
        }
    }
    writingspacelock.unlock();
    
    cout << endl<< "size post 9696 id " << blData.size();
    addHexStringInVector(blData, "9696"); // end of blocks
    addHexStringInVector(uncompressedbl, "9696");


    std::unique_lock<std::mutex> blRefactHashedBlockmtxlock(blRefactHashedBlockmtx);

    blRefactHashedAnt=blRefactHashed;
    blRefactHashed.clear();

    blRefactHashed= sha3_256v(uncompressedbl);

    blRefactHashedBlockmtxlock.unlock();

    cout<<endl<<endl<<"bl refactvalidate write uncompressed : "<<endl;
    for(uint i = 0; i < uncompressedbl.size();i++){
        cout<<byteToHex2(uncompressedbl[i]);
    }

    cout<<endl<<endl;
    cout<<endl<<endl<<"bl refactvalidate is  : "<<endl;

    for (uint8_t i = 0; i <blRefactHashed.size();i++){
        blData.push_back(blRefactHashed[i]);
        cout<<byteToHex2(blRefactHashed[i]);
    }

}

bool ValidateBlockNetwork(vector<unsigned char> &blRefactHashedAnt){

    while(time(nullptr)<timingbl+120){

        uint sums = 0;
        uint Discardsums = 0;
        std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
        auto Nodes2 = Nodes;

        peerssyncblocklock.unlock();

        auto it = Nodes2.begin();
        while (it != Nodes2.end()) {

            cout<<endl<<"debug refact blRefactHashedQueryNode "<<it->second.ip<<endl;

            if(it->second.ip== "localhost" ){
                sums++;
                cout<<endl<<"sums "<<sums<<endl;
                ++it;
                continue;
            }

            vector<unsigned char> result =  blRefactHashedQueryNode(it->second.ip);
            if( result == blRefactHashed){
                sums++;
                cout<<endl<<"sums "<<sums<<endl;
            } else {
                if(result.size() == 32&&result!= blRefactHashedAnt ){
                    Discardsums++;
                    cout<<endl<<"Discardsums "<<Discardsums<<endl;
                }else {
                cout<<endl<<"refact validate skip bad response from node   "<<it->second.ip<<endl;
                }
            } 
            ++it;

        }
        if((sums*10000)/Nodes2.size() >= 5100 ) {
            cout<<endl<<"block"<<lastblockbuild()+1<<" Validate by "<<sums<<" of "<<Nodes2.size()<<endl;
            return true;
        }
        if((Discardsums*10000)/Nodes2.size() >= 5000 ) {

            cout<<endl<<"discar block refact by "<<Discardsums<<" of " <<Nodes2.size()<<endl;
            
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

    if (Refactorizing){
        // handle error
        return "...Refact new bl";
    }
 
    cout<<endl<<"refact validate alg init =====>"<<endl;

    vector<unsigned char> byteArray;
    vector<unsigned char> uncompressedbl;
    vector<unsigned char> blRefactHashedAnt;
    
    BuilBLDataArray(blRefactHashedAnt, byteArray, uncompressedbl);

    if(!ValidateBlockNetwork(blRefactHashedAnt)){
        postRefactRoundInit = false;
        Refactorizing = false;
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

    cout<<endl<<" write new bl "<<lastbl<<" success";

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

    cout<<endl<<"refact validate post blkQueuemtxlock"<<endl;

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
        cout<<endl<<endl<<endl<<"debug refact blksOPSyncQueue.size() ;"<<blksOPSyncQueue.size() <<endl<<endl<<endl;
        lastmatchsyncqueue = blksOPSyncQueue.size() ;
    }else {
        BlAntIsMatch = false;
        lastmatchsyncqueue = 0;
        blksOPSyncQueue.clear();
    }

    blkQueuemtxlock.unlock();

    LBBBuffered = blread(to_string(lastblockbuild()));
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
    cout<<endl<<"debug end refactory alg "<<endl;
    return "ok";
}

string DataTransac(string &From, string &to, uint64_t cant,uint32_t percentfeed){

    extern const string idBlckchn;
    extern string ShaLBBBuffered;

    if (From.length() != 130 || to.length() != 130){ return "Invalid address";}
    if (to.substr(0, 2) != "04" || From.substr(0, 2) != "04"){return "Invalid address";}
    if (!HexCheck(From) || !HexCheck(to)){return "Invalid_Characters";}
    if (From == to) {return "same addresses";}
    if(cant<1){return "value transac < 0";}
    for (auto &s : From){ s = toupper(s);}
    for (auto &s : to){ s = toupper(s);}

    array <unsigned char,64> accarrL = accArr(From.substr(2,128));
    array <unsigned char,64> accarrR = accArr(to.substr(2,128));

    // indexing of sender
    string verifier_index =searchlastmove( From,true);
    cout<<endl<<"debug  From acc: "<<From<<endl;
    cout<<endl<<"debug verifier_index From value: "<<verifier_index<<endl;

    if (!HexCheck(verifier_index)){
        cout<<endl<<"DataTransac error !HexCheck(verifier_index) ";
        return verifier_index;
    }

    uint64_t value = hexToULL(verifier_index);
    uint feed = percent(cant, percentfeed);
    cout<<endl<<"percentfeed "<<percentfeed<<endl;
    cout<<endl<<"feed "<<feed<<endl;


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

    cout<<endl<<"debug verifier_index to value: "<<verifier_index<<endl;

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

    cout<<endl<<"debugdatatransac() bytearray transac before hidden "<<byteArray.size()<<endl;
    // hidden

    string ShaMin = matchMinQueue();
    for (auto &s : ShaMin){s = toupper(s);}
    ShaMin = SHAstg(ShaMin);

    string hidden =idBlckchn+blckheader+ ShaMin;
    addHexStringInVector(byteArray, hidden); 
    string data = vectorstring(byteArray);
    for (auto &s : data){ s = toupper(s); }

    cout<<endl<<"end datatransac "<<byteArray.size()<<endl;

    return data;
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

    string PublicSigner = readaccountString(signedT, false);
    string PublicReceiver = readaccountString(signedT, true);
    string blcknmbr = blOpNmbr(signedT);
    string ShaMin = matchMinQueue();
    for (auto &s : ShaMin){s = toupper(s);}
    ShaMin=SHAstg(ShaMin);
    for (auto &s : ShaMin){s = toupper(s);}
    string datatransacString = signedT.substr(0, 494);
    string FIRM_READ = signedT.substr(494, 128);

    cout<<endl<<"transacsigendpost 1"<<endl;
    cout<< endl<<"debug st2 firms "<<endl<<" verifisignature datatransacString "<<datatransacString<<endl<<endl;
    cout<< " verifisignature FIRM_READ "<<FIRM_READ<<endl<<endl;
    cout<< " verifisignature PublicSigner "<<PublicSigner<<endl<<endl;

    if (verifySignature(datatransacString, FIRM_READ, loadPublicKey(PublicSigner))  ){
        cout<<endl<<"transacsigendpost 2"<<endl;
        if (FIRMCheck2(signedT.substr(0, 302) + FIRM_READ, idBlckchn + shaLBB() + ShaMin)){

            cout<<endl<<"transacsigendpost 3"<<endl;
            vector<unsigned char> byteArray;
            addHexStringInVector(byteArray, signedT.substr(0, 302) + FIRM_READ);
            string datafromArr = vectorstring(byteArray);
            for (auto &s : datafromArr){s = toupper(s);}

            std::unique_lock<std::mutex> writingspacelock(writingspace);

            if(switchBlType(blksOP[ hexToInt(blOpNmbr(signedT))-1])!= datatransacString){
                std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);
                transacpendingcount--;
                return "error signed transac blksOP[ hexToInt(blOpNmbr(signedT))]!= datatransacString";
            }

            
            
            blksOP[hexToInt(blcknmbr)-1] = signedT.substr(0, 302) + FIRM_READ;
            writingspacelock.unlock();

            array <unsigned char,64> accarrL = accArr(PublicSigner);
            array <unsigned char,64> accarrR = accArr(PublicReceiver);

            std::unique_lock<std::mutex> WritingAccSynclock(WritingAccSync);

            if(typebl(signedT) == "00") {
                AccSync[accarrL].value = hexToULL(readbalanceString(signedT, false));
                AccSync[accarrR].value = hexToULL(readbalanceString(signedT, true));
            }

            if(typebl(signedT) == "04"){
                AccSync[accarrL].value -= hexToULL(readbalanceString(signedT, false))+hexToUint(FeedOfTransac(datatransacString));
                AccSync[accarrR].value += hexToULL(readbalanceString(signedT, true));
            }

            if(typebl(signedT) == "06"){
                AccSync[accarrL].value = hexToULL(readbalanceString(signedT, false));
                AccSync[accarrR].value += hexToULL(readbalanceString(signedT, true));
            }

            if(typebl(signedT) == "08"){
                AccSync[accarrL].value -= hexToULL(readbalanceString(signedT, false))+hexToUint(FeedOfTransac(datatransacString));
                AccSync[accarrR].value = hexToULL(readbalanceString(signedT, true));
            }

            WritingAccSynclock.unlock();

            std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);
            transacscomfirmed++;
            pricesingtransacCountlock.unlock();
            
            extern string dir_feeds;

            if ( matchMinQueueIp() == "localhost"){
                std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);
                blksOPSyncQueue.push_back(intToHex(hexToInt(blOpNmbr(signedT))-1)+signedT.substr(0, 302)+FIRM_READ );
                blkQueuemtxlock.unlock();
            }

            pricesingtransacCountlock.lock();
            transacpendingcount--;
            pricesingtransacCountlock.unlock();


            if (transacscomfirmed == blksize){
                cout<<endl<<"refact validate alg init =====>"<<endl;
                refactvalidate();
            }

            if (transacscomfirmed > blksize){
                cout<<endl<<"error refactvalidate transacscomfirmed > blksize"<<endl;
                exit_call();
            }

            return "SUCESS! - Block: " + signedT.substr(0, 302)+ FIRM_READ;
        } 
    }


    std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);
    transacpendingcount--;
    return "FAIL VERIFICATION: " + signedT;
}

#endif

