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

#include <curl/curl.h>
#include <string>
#include <iostream>


using namespace std;

struct ResponseData {
    string data;
    long responseCode;
};

// Función para manejar la respuesta de la solicitud
size_t writeCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    string* response = reinterpret_cast<string*>(userdata);
    response->append(ptr, size * nmemb);
    return size * nmemb;
}

string curlpost2(string url, string postfield, int timeout_ms) {
  CURL *curl;
  CURLcode res;

  timeout_ms = 4000;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  string s;
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false); //verificar que las peticiones esten encriptadas
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfield.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    //curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
      cerr << "req error : " <<url<<" : "<< curl_easy_strerror(res) << endl;
      s = "00";
    }

    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();
  return s;
}

string curlpost(string url, string postfield, int timeout_ms){

      timeout_ms = 4000;
    std::string response;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    // Create a cURL handle
    CURL* curl = curl_easy_init();

    if (curl) {
        // Set the target URL
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false); //verificar que las peticiones esten encriptadas
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfield.c_str());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        // Perform the request asynchronously
        curl_multi_init();
        CURLM* curlm = curl_multi_init();
        curl_multi_add_handle(curlm, curl);
        int runningHandles;
        do {
            curl_multi_perform(curlm, &runningHandles);
        } while (runningHandles > 0);

        // Print the response
       // std::cout << "Response curlpost2: " << response << std::endl;

        // Cleanup
        curl_multi_remove_handle(curlm, curl);
        curl_multi_cleanup(curlm);
        curl_easy_cleanup(curl);

        return response;
    }

    // Cleanup cURL
    curl_global_cleanup();
    return "curl internal error";

}


