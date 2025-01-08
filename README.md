## CryptoDbSS Project, Blockchain core, consensus, protocols and misc.
<p align="center">
  <img src="https://github.com/Steeven512/CryptoDbSS/blob/main/CryptoDbSSLogo.png" alt="Alt Text" width="250" height="250">
</p>
</br>

> [!WARNING]
> This Software is a prototype version, it should only be used for study, review and audit purposes, please read the license and its terms of use carefully.

</br></br>
CryproDbSS is a Blockchain Software technology, developing on being faster,
light and optimized, with secure and scalable design focus on its algorythms, 
writed on C++ brings perfomance and portability.

Presents a proposal consensus called Matchmin. Its arrange a list 
queue with each node on pseudorandomness for build the next blocks in chain, 
no need an extensive power of compute consume and provides transparency 
allowing all nodes participate and reward feeds.

Can process a big flow of transacs/operations asynchroniusly meanwhile the
status of accounts/addresses is defined.

Each Block can contain an amount of 65500 Operations/Transacs.

Standar transactions has a storage length of [215 bytes], but with the 
algorythms of Compression reduces the size with diferents posible 
levels, the max can be result on [83 bytes] of length storage size per 
transac.

Faster indexing and caching account/addresses and hashes in memory, 
each block could be build on a chain in a few seconds or less.

The design of the structure of db blocks and transacs
haves indentifyers for diferency the types of transactions and/or 
operations, it's allowing obtain the asynchroniusly between transactions, 
diferent compress levels, this feature bring a very scalable design
for add some few future features like others cryptografy elliptic 
curves, run Smart Contracs and more, the Mind is the limit.

the design of the code provides security algorythms, it's check the binary 
integrity of the entire DB and the sums value of the addresses in each 
transac at the chain.

### Third-party dependencies: 
> CrowCpp, Crypto++, OpenSSL, Boost, ASIO, libcurl.

### Build on GNU/Linux Debian with:
> src/CryptoDbSS.cpp -o CryptoDbSS -lpthread -DCROW_ENABLE_SSL -lssl -lcrypto -lcryptopp -DCURL_STATICLIB -lcurl -std=c++17

# Get more Info And Updates
Follow the blog [cryptodbss.blogspot.com](https://cryptodbss.blogspot.com/).

#

<p align="center">
  </br>
questions, suggestions or contact : Steevenjavier@gmail.com
</br></br>
 Copyright (C) 2025 Steeven J Salazar.
</p>






