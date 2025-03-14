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
