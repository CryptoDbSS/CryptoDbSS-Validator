							
							Instructions

	before you can use, compile, read, audith or do anything with this 
	software and its derivatives you first need to read and accept the 
	agreements specified in the LICENSE.txt provided in this package, 
	otherwise,you will not be able to continue using nothing about this 
	package..
	

third parties dependences for build app

for compiling, use: 

	g++ src/CryptoDbSS.cpp -o CryptoDbSS -lpthread -DCROW_ENABLE_SSL -lssl -lcrypto -lcryptopp -DCURL_STATICLIB -lcurl -std=c++17

Initial setup app

    key node: The configuration of this is necessary to connect in a 
    blockchain network, each node must have a unique key, It derives its 
	public address, which it will use to identify itself to others and 
	generate cryptographic signatures for authenticate the 
    data, providing security in the network, Additionally, it will be used 
	to write the metadata of the block that its will build. The privkey is stored 
    at "/node/priv" directory, open the file with a text editor and 
    place the private key, it should be a 64 length of hex format 
    characters, example:
	"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    
    genesis block:This package contains a tool to forge genesis blocks, 
    this must be compiled but before is necessary to specify the address
    and its value at the source code of the utility that will be started 
    with the new network, the file sources is on "src/BuildGenesis.cpp, its
    contains the compiling details info.

client side app

	the core-prototype have a client, served via https, you can access it
	through a browser at the address https://0.0.0.0:18090

	the client can make transactions, create/derive and save locally 
	crypto-accounts, index balance of accounts, index transactions by Number 
	or hash and see other relational info of interest.

	for create an account you first need your private key, for the 
	secp256k1 schema it shoud be a string with hex chars with a long of 
	64 chars, in otherwise a 32bytes lengt representation, the client 
	have a tool for hash any string that represent the private key andm 
	its can be use to returns the desire length chars.
	
	
	
admin side app

	for setup the node parameters and its network, the core-prototype 
	serve an setting admin panel on the address 0.0.0.0:19080/NodeSet 
	
	For security reasons it is only possible to be accessed via locally.
	
	at the top of the page you can see the node info like the 
	blockchain name/id, the public address of node, ect.
	
	then at Node Sync Network section, It displays the nodes on the network 
	paired, their status, and a buttom for setup each.
	
	bellow, at the "Save new public Node" you can add nodes that operate 
	on the network by parsing their public addresses, The new registered 
	address appears in the "Node Sync Network" section. You must configure 
	they IP addresses by clicking edit settings and adding it, for example: 
	12.345.678.57:18090
	
	the last section contains the miscellaneous setting parameters of 
	the nodes, each option describes the operation by itself, beware with
	the parameters values.
	

create/Derive accounts-wallets

	at the client side https://0.0.0.0:18090/derivat, enter in the first
	form the priv key , it should be a 64 length of hex characters 
	format example:
	<9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08>
	
	remember, never share it with anyone, and you should store it on a 
	secure way.
	
	optional, you can use de hash function below for convert any string 
	on a string of 64 hex value, example enter the word "test" and will 
	show:
	<9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08>
	
	then you enter the private key push the bottom at the right side and 
	will show:
	<045f81956d5826bad7d30daed2b5c8c98e72046c1ec8323da336445476183fb7ca54ba511b8b782bc5085962412e8b9879496e3b60bebee7c36987d1d5848b9a50>
	(this is an uncompressed format of secp256k1 schema ec public key )
	
	That is the public address, and is used for others to transfer to 
	it, and index its value
	

	
	
	
	
	
	





