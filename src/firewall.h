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

#ifndef FIREWALL_H
#define FIREWALL_H

#include<iostream>
#include "CryptoDbSS.cpp"

using namespace std;

struct ReqIp{
    uint loginAlg;
    uint transacAlg;
    uint syncTransacAlg;
    uint front;
    uint balanceindex;
    uint blocksearch;
    uint status;
    
    };

extern unordered_map<string, ReqIp> AllowIp;
extern forward_list<string> BanIp;
extern uint loginAlg;
extern uint transcAlg;
extern uint syncTransacAlg;
extern uint front;
extern uint balanceindex;
extern uint blocksearch;
extern uint status;
extern bool firewallcheck;
extern mutex allowIpmtx;


void denyIp(string ip){
    BanIp.push_front(ip);
}

void warningIp(string ip){
    extern unordered_map<string, uint> WarningIp;
    WarningIp[ip]++;
    if( WarningIp[ip]>2 ){
        denyIp(ip);
    }
}


string firewall(string ip, string route){

    firewallcheck = true;
    std::unique_lock<std::mutex> allowIpmtxlock(allowIpmtx);

    return "true";

    auto it  = find(BanIp.begin(), BanIp.end(), ip);
    if (it != BanIp.end()){
        cout<<endl<<"request from ; "<<ip<< " DENY; Reason Ban";
        firewallcheck = false;
        return "request from ; "+ip+" DENY; Reason Ban";
        } 

    if(route == "loginAlg"){

        if(AllowIp[ip].loginAlg>loginAlg){
            firewallcheck = false;
            cout<<endl<<"Deny request from ; "<<ip<< " reason: Too many request";
            return "request from ; "+ip+ " reason: Too many request";
        } else { 
            AllowIp[ip].loginAlg++;
            firewallcheck = false;
            return "true";}
    }

    if(route == "transcAlg"){

        if(AllowIp[ip].transacAlg>transcAlg){
            firewallcheck = false;
            cout<<endl<<"request from ; "<<ip<< " reason: Too many request";
            return "request from ; "+ip+ " reason: Too many request";
        } else { 
            AllowIp[ip].transacAlg++;
            firewallcheck = false;
            return "true";}
    }

    if(route == "syncTransacAlg"){

        if(AllowIp[ip].syncTransacAlg>syncTransacAlg){
            firewallcheck = false;
            cout<<endl<<"request from ; "<<ip<< " reason: Too many request syncTransacAlg";
            return "request from ; "+ip+ " reason: Too many request syncTransacAlg";
        } else { 
            AllowIp[ip].syncTransacAlg++;
            firewallcheck = false;
            return "true";}
    }

    if(route == "front"){

        if(AllowIp[ip].front>front){
            firewallcheck = false;
            cout<<endl<<"Deny request from : "<<ip<< " reason: Too many request";
            return "Deny request from : "+ip+ " reason: Too many request";
        } else { 
            AllowIp[ip].front++;
            firewallcheck = false;
            return "true";}
    }

    if(route == "balanceindex"){

        if(AllowIp[ip].balanceindex>balanceindex){
            firewallcheck = false;
            cout<<endl<<"Deny request from : "<<ip<< " reason: Too many request";
            return "Deny request from : "+ip+ " reason: Too many request";
        } else { 
            AllowIp[ip].balanceindex++;
            firewallcheck = false;
            return "true";}
    }

    if(route == "blocksearch"){

        if(AllowIp[ip].blocksearch>blocksearch){
            firewallcheck = false;
            cout<<endl<<"Deny request from : "<<ip<< " reason: Too many request";
            return "Deny request from : "+ip+ " reason: Too many request";
        } else { 
            AllowIp[ip].blocksearch++;
            firewallcheck = false;
            return "true";}
    }

    if(route == "status"){

        if(AllowIp[ip].status>status){
            firewallcheck = false;
            cout<<endl<<"Deny request from : "<<ip<< " reason: Too many request";
            return "Deny request from : "+ip+ " reason: Too many request, status call";
        } else {status++;
            firewallcheck = false;
            return "true";}
    }


    return "internal server error";



}

#endif
