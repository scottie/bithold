// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2014-2015 Dash Developers
// Copyright (c) 2017-2018 The Bithold developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"
#include "chainparams.h"
#include "main.h"
#include "util.h"
#include "base58.h"
#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds array into usable address objects.
static void convertSeeds(std::vector<CAddress> &vSeedsOut, const unsigned int *data, unsigned int count, int port)
{
     // It'll only connect to one or two seed nodes because once it connects,
     // it'll get a pile of addresses with newer timestamps.
     // Seed nodes are given a random 'last seen time' of between one and two
     // weeks ago.
     const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int k = 0; k < count; ++k)
    {
        struct in_addr ip;
        unsigned int i = data[k], t;
        
        // -- convert to big endian
        t =   (i & 0x000000ff) << 24u
            | (i & 0x0000ff00) << 8u
            | (i & 0x00ff0000) >> 8u
            | (i & 0xff000000) >> 24u;
        
        memcpy(&ip, &t, sizeof(ip));
        
        CAddress addr(CService(ip, port));
        addr.nTime = GetTime()-GetRand(nOneWeek)-nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

// Hardcoded seeds.
static void getHardcodedSeeds(std::vector<CAddress> &vSeedsOut)
{
    std::vector<std::string> ips;
    //ips.push_back("54.37.233.83");
    //ips.push_back("137.74.40.196");
    //ips.push_back("144.217.4.129");
    //ips.push_back("185.241.53.228");
	
    const int64_t oneWeek = 7 * 24 * 60 * 60;
    for (size_t i = 0; i < ips.size(); ++i)
    {
        CAddress addr(CService(ips[i], 15971));
        addr.nTime = GetTime() - GetRand(oneWeek) - oneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xf7;
        pchMessageStart[1] = 0xe3;
        pchMessageStart[2] = 0xa2;
        pchMessageStart[3] = 0xb6;
        vAlertPubKey = ParseHex("0496231e15af76eb1d0e4a656ed3594ef64425850aa52617506177cf245575f0aa11e5b1777cfd8621ea39a7996872a07631ea25b3fdda00df37f5e982fe58850a");
        nDefaultPort = 15971;
        nRPCPort = 15973;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16); // starting difficulty is 1 / 2^12
		
        const char* pszTimestamp = "3/22/2018 4:30am BTC/USD $8774, A new Chapter was created";
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
		
        CTransaction txNew(1, 1521653362, vin, vout, 0);

        LogPrintf("genesis mainnet transaction:  %s\n", txNew.ToString().c_str());

        genesis.vtx.push_back(txNew);

        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1430677023; // Wednesday, 17-Jan-18 02:00:01 UTC
        genesis.nBits    = bnProofOfWorkLimit.GetCompact(); 
        genesis.nNonce   = 571396;
	
        /*
        if(genesis.GetHash() != uint256("0x"))
        {
            printf("Looking for genesis block...\n");
            uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
            while(uint256(genesis.GetHash()) > hashTarget)
            {
                ++genesis.nNonce;
                if (genesis.nNonce == 0)
                {
                    printf("NONCE WRAPPED, incrementing time");
                    std::cout << std::string("NONCE WRAPPED, incrementing time:\n");
                    ++genesis.nTime;
                }
                if (genesis.nNonce % 10000 == 0)
                {
                    printf("Mainnet: nonce %08u: hash = %s \n", genesis.nNonce, genesis.GetHash().ToString().c_str());
                }
            }
            printf("merkle root: %s\n", genesis.hashMerkleRoot.ToString().c_str());
            printf("block.nTime = %u \n", genesis.nTime);
            printf("block.nNonce = %u \n", genesis.nNonce);
            printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        }
        */
        hashGenesisBlock = genesis.GetHash();

        std::cout << hashGenesisBlock.GetHex() << "\n";
        std::cout << "Merkle: " << genesis.hashMerkleRoot.GetHex() << "\n";

        assert(hashGenesisBlock == uint256("0x24301d47fa220bcd03c99658361081e4b67ea8dd45a674b39dc5f5ca201b2b40"));
        assert(genesis.hashMerkleRoot == uint256("0x79443a044c85d8abcbe7eb0defbf08b8ca9c0a99df3a97881f399f47fed4e568"));

        
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,80); // z
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,31);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,24);
        base58Prefixes[STEALTH_ADDRESS] = std::vector<unsigned char>(1,51);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x92)(0x72)(0x42)(0xE2).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x92)(0x71)(0x44)(0xE5).convert_to_container<std::vector<unsigned char> >();  
	
        //vSeeds.push_back(CDNSSeedData("1",  "54.37.233.83"));
        //vSeeds.push_back(CDNSSeedData("2",  "137.74.40.196"));
        //vSeeds.push_back(CDNSSeedData("3",  "144.217.4.129"));
        //vSeeds.push_back(CDNSSeedData("4",  "185.241.53.228"));
		
		convertSeeds(vFixedSeeds, pnSeed, ARRAYLEN(pnSeed), nDefaultPort); 
		
        getHardcodedSeeds(vFixedSeeds);		

        nPoolMaxTransactions = 3;
        strDarksendPoolDummyAddress = "hFoQDUrp63QWqFhjEr3Fmc4ubHRhyzjKUC";

        nLastPOWBlock = 1500000;
        nPOSStartBlock = 500;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xe5;
        pchMessageStart[2] = 0xa6;
        pchMessageStart[3] = 0xb8;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        vAlertPubKey = ParseHex("0496131e15af76eb1d0e4a656ed3594ef64425850aa52617506177cf245575f0aa11e5b1777cfd8621ea39a7996872a07631ea25b3fdda00df37f5e982fe58850a");
        nDefaultPort = 27170;
        nRPCPort = 27171;
        strDataDir = "testnet";
        genesis.nTime    = 1516154411;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact(); 
        genesis.nNonce   = 38881;

        hashGenesisBlock = genesis.GetHash();
        //assert(hashGenesisBlock == uint256("0x0000ff2b37540864619169d162127548e496c393ccbd535fa4077ddf587b75bb"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,102); // h
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,23);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,25);
        base58Prefixes[STEALTH_ADDRESS] = std::vector<unsigned char>(1,43);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x98)(0x74)(0x44)(0xE1).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x98)(0x72)(0x42)(0xE2).convert_to_container<std::vector<unsigned char> >();

        convertSeeds(vFixedSeeds, pnTestnetSeed, ARRAYLEN(pnTestnetSeed), nDefaultPort);

        nLastPOWBlock = 400000;
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    
    bool fTestNet = GetBoolArg("-testnet", false);
    
    if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}