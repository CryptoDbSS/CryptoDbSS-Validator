## CryptoDbSS Project, Blockchain core, consensus, protocols and misc.
<p align="center">
  <img src="https://github.com/Steeven512/CryptoDbSS/blob/main/CryptoDbSSLogo.png" alt="Alt Text" width="250" height="250">
</p>


## Overview

**CryptoDbSS** is a **blockchain software technology** written in **C++**, designed to be **fast, lightweight, and optimized**. It focuses on **security, scalability, and performance**, with a unique consensus mechanism called **Matchmin**. As a **comprehensive framework**, integrates software and protocols based on blockchain and cryptography,, serving as an **engine** for executing:

- **Blockchains**: A decentralized and secure ledger for recording transactions.
- **Decentralized Applications (DApps)**: Applications that run on a peer-to-peer network rather than a centralized server.
- **Accounting Ledgers**: Transparent and immutable records of financial transactions.
- **Asset Tracing**: Tools for tracking and verifying the ownership and movement of digital assets.

The architecture of CryptoDbSS features **robust security algorithms**, **high execution performance**, and **scalability**, making it suitable for a wide range of use cases. By leveraging advanced cryptographic techniques and optimized data structures, it enhances **operational efficiency** and **trust** in decentralized systems.

---

## Key Features

### 1. **Matchmin Consensus**
- A novel consensus algorithm that uses **pseudorandomness** to arrange nodes in a queue for block creation.
- Does not require extensive computational power (unlike Proof of Work).
- Ensures **transparency** and allows all nodes to participate and receive rewards.

### 2. **High Throughput**
- Can process a **large flow of transactions/operations asynchronously**.
- Each block can contain up to **65,500 transactions/operations**.

### 3. **Transaction Compression**
- Standard transactions are **215 bytes** in size, but compression algorithms can reduce this to as low as **83 bytes**.
- Multiple compression levels are available.

### 4. **Performance**
- Faster indexing and caching of accounts/addresses and hashes in memory.
- Blocks can be built in **seconds or less**.

### 5. **Scalable Design**
- The structure of the database (blocks and transactions) supports **asynchronous transactions** and different compression levels.
- Designed to easily add future features, such as:
  - Support for additional cryptographic elliptic curves.
  - Smart contract functionality.

### 6. **Security**
- Includes algorithms to check the **binary integrity** of the entire database.
- Verifies the **sums of address values** in each transaction across the chain.

---

## **Setup and Usage**

  ### **1. License Agreement**

  - Before using, compiling, reading, auditing, or doing anything with the software or its derivatives, **you must read and accept the agreements** specified in the **LICENSE.txt** file provided in the package.

  ### **2. Compiling the Application**

  
  The CryptoDbSS relies on the following libraries:
  
  > CrowCpp, Crypto++, OpenSSL, Boost, ASIO, libcurl.

   To compile the application, use the following command:
   
   ``` g++ src/CryptoDbSS.cpp -o CryptoDbSS -lpthread -DCROW_ENABLE_SSL -lssl -lcrypto -lcryptopp -DCURL_STATICLIB -lcurl -std=c++17 ```
   

  ### **3.Initial Setup**

  - **Node Key Configuration:**

    - Each node in the blockchain network must have a **unique private key**.
    - The private key is used to:
      - Derive the node's *public address*.
      - Generate cryptographic signatures for authenticating data.
      - Write metadata for blocks created by the node.

    - The private key is stored in the file /node/priv. Open this file with a text editor and insert a **64-character           hexadecimal private key**. Example:

        ```9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 ```

  - **Genesis Block:**
    
    - Use the **BuildGenesis.cpp** tool to forge a genesis block.
    - Specify the address and its value in the source code before compiling.
   


  ### **4. Client-Side Application**
  
  - Access the client via HTTPS at:

    ``` https://0.0.0.0:18090 ```
  
  - Features:
    
    - Create/derive accounts.
    - Make transactions.
    - Index balances and transactions.
    - Use a hash function to generate private keys.

### **5. Admin-Side Application**

 - Access the admin panel locally at:

   ```http://0.0.0.0:19080/NodeSet```

- Features:

  - Configure node parameters.
  - Manage network nodes (add, sync, and configure IP addresses).
  - Adjust miscellaneous settings.
    
  </br>
  
---

# Get more Info And Updates

  </br>
<p align="center">Follow the blog <a href="https://cryptodbss.blogspot.com" > cryptodbss.blogspot.com </a> </p>

<p align="center">questions, suggestions or contact : Steevenjavier@gmail.com
</br></br>
 Copyright (C) 2025 Steeven J Salazar.
</p>






