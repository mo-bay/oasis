// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The oasis developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libzerocoin/Params.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>
#include <limits>

#include "chainparamsseeds.h"

std::string CDNSSeedData::getHost(uint64_t requiredServiceBits) const {
    //use default host for non-filter-capable seeds or if we use the default service bits (NODE_NETWORK)
    if (!supportsServiceBitsFiltering || requiredServiceBits == NODE_NETWORK)
        return host;

    return strprintf("x%x.%s", requiredServiceBits, host);
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of the genesis coinbase cannot
 * be spent as it did not originally exist in the database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "UK NEWS 26-05-2018 - UK Economy could start to pick up, says Bank of England governor ---Remapper,Pesh---Made in England";
    const CScript genesisOutputScript = CScript() << ParseHex("142292b1f401860eea99e1a8a103effbd7e1c013a59a1a3a0c91c9d1997a0bc6f338567278c11344802838c107055bf7c1641eaed61e879245c255a4f5be5746fc") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
                (0, uint256("0x00000d928efd171c0d8435d457d9becf8542c8e19ddb560dc9e08189014f6617"))
                (1, uint256("0x000002cb5693188479b0634f5b5edb1357674b9bf20b2b17b5ca5b5c540fd7e3"))
                (8, uint256("0x000002477df15df6a08518bd924b7815ead096c3421c6dbcb96eb49f2ce9b6af"))
                (32, uint256("0x000005fb2690cf8a5655f5b5a4f034e5bc463aac27de102c2f8182abcf58149d"))
                (128, uint256("0x000001e9ce3c7b697143a85733bea949f12b3838f29b71fcbcad851016092b66"))
                (512, uint256("0x9b6153f6cdcda28d64de05ba16a0cf10b67e731270e76e6021fa44d615b34a8c"))
                (2048, uint256("0xe623bb9b9218a7dc1ac331ea107f7c2824afe1502918f4eff2cc7714a29f86f0"))
                (8192, uint256("0xf7a38982b2daecdcec76d7dba95107681f29c4898fbfd6760342edc8ad4cbeef"))
                (32768, uint256("0xa18281199b89155587bf721291f2fcb1ffb075372e5afe298adbd138c8778c4a"))
                (131072, uint256("0x9b824b20927aaf615343858e066c80b8991fb406447f2a5d33b1561bce6d8eb7"))
                (262144, uint256("0x16d0e036281c22593c4e65791ae8d9932596907a2bd316d34bc109e51065c2af"))
                (315204, uint256("0xab424d044357b3db106a8256cf840da72fa07f93c4548f5993b7b863d618fcbe"));
static const Checkpoints::CCheckpointData data = {
        &mapCheckpoints,
        1546306998, // * UNIX timestamp of last checkpoint block
        632503,     // * total number of transactions between genesis and last checkpoint
        //   (the tx=... number in the SetBestChain debug.log lines)
        2000        // * estimated number of transactions per day after checkpoint
};


static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1740710,
    0,
    250};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1454124731,
    0,
    100};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";

        printf("Mainnet Genesis hashMerkleRoot=: =======>%s\n", genesis.hashMerkleRoot.ToString().c_str());
        
        //genesis = CreateGenesisBlock(1527359509, 737213, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
         printf("Mainnet Genesis Hash=: =======>%s\n", genesis.GetHash().ToString().c_str());

        //assert(consensus.hashGenesisBlock == uint256("00000d928efd171c0d8435d457d9becf8542c8e19ddb560dc9e08189014f6617"));
        assert(genesis.hashMerkleRoot == uint256("92efca81c11c8026ae8ee4fc743aee0e458f5b9866b917c381b0d3a1e7edda63"));

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // oasis starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 43200;       // approx. 1 every 30 days
        consensus.nBudgetFeeConfirmations = 16;      // Number of confirmations for the finalization fee
        consensus.nCoinbaseMaturity = 10;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMasternodeCountDrift = 20;       // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 300000 * COIN;
        consensus.nPoolMaxTransactions = 3;
        consensus.nProposalEstablishmentTime = 60 * 60 * 24;    // must be at least a day old to make it into a budget
        consensus.nStakeMinAge = 60 * 60;
        consensus.nStakeMinDepth = 600;
        consensus.nTargetTimespan = 1 * 30;
        consensus.nTargetTimespanV2 = 1 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;
        consensus.strObfuscationPoolDummyAddress = "oSQo21b24dD6AvQ2QyAfQFdBHTSw894tJb";

        // spork keys
        consensus.strSporkPubKey = "04b080934472357368be9982a8c138968958267ff5de3d70d92d2d436642dd1da3976b2b1ec62f934a6b925fc1ccab32205580d1d50554fb1da3c2d8b964c15d3d";
	
	/// height-based activations - // Actual figures noted after chain was fixed and moving.
        consensus.height_last_PoW = 200;
        consensus.height_RHF = 1620500; //82e98476d3865d29dec0a9f75988413248856e774a3434a714a7f1e3b558ef81
        consensus.height_last_ZC_AccumCheckpoint = INT_MAX;
        consensus.height_start_BIP65 = consensus.height_RHF;  // 3367b6142ecf62e6526c4b01abd19a3783a9144c20b72311c3e97708b86791b0 - block v5 (default)
        consensus.height_start_MessSignaturesV2 = consensus.height_RHF;  // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_StakeModifierNewSelection = 1620435; //initial stakemodifier will start few blocks before the stakemodifierv2 14425f092cec36beee5e163aa54995f520e00544f579af24281e13994c208edb
        consensus.height_start_StakeModifierV2 = 1620445; //block f131368ce97278f1ea56654703fd559ba0cfbf2a3ae5bcab09b4ad584ef0f07b
        consensus.height_start_TimeProtoV2 = consensus.height_RHF;;       // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_ZC = 201; // block v4 376b848ad5d83b15f04690520e1d6bf33cb7129e41a3d822b583a6818a6237b5
        consensus.height_start_ZC_PublicSpends = INT_MAX;
        consensus.height_start_ZC_SerialRangeCheck = INT_MAX;
        consensus.height_start_ZC_SerialsV2 = INT_MAX;
	
        // Zerocoin-related params
        consensus.ZC_Modulus = "2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363""7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 20;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 200;
        consensus.ZC_TimeStart = 1527415096; // 2018-05-27T09:58:16Z

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x53;
        pchMessageStart[1] = 0x43;
        pchMessageStart[2] = 0x39;
        pchMessageStart[3] = 0x26;
        nDefaultPort = 2358;

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("18.188.43.235", "18.188.43.235"));// Single node - MN runs for more than half a year
        vSeeds.push_back(CDNSSeedData("35.177.169.240", "35.177.169.240"));// Single node - MN runs for more than half a year
        vSeeds.push_back(CDNSSeedData("35.178.43.213", "35.178.43.213"));// Single node - MN runs for more than half a year
        vSeeds.push_back(CDNSSeedData("80.211.46.189", "80.211.46.189"));// Single node - MN runs for more than half a year
        vSeeds.push_back(CDNSSeedData("80.211.33.67", "80.211.33.67"));// Single node - MN runs for more than half a year
        vSeeds.push_back(CDNSSeedData("18.218.209.226", "18.218.209.226"));// Single node - MN runs for more than half a year
        vSeeds.push_back(CDNSSeedData("51.15.89.68", "51.15.89.68"));// Single node - MN runs for more than half a year
        vSeeds.push_back(CDNSSeedData("167.99.193.12", "167.99.193.12"));// Remapper1
        vSeeds.push_back(CDNSSeedData("178.62.68.177", "178.62.68.177"));// Remapper2
        vSeeds.push_back(CDNSSeedData("oasis.seeds.mn.zone", "oasis.seeds.mn.zone")); // Third party DNS Seeder
        vSeeds.push_back(CDNSSeedData("oasis.mnseeds.com", "oasis.mnseeds.com")); // Third party DNS Seeder

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 115);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 15);
        base58Prefixes[STAKING_ADDRESS] = std::vector<unsigned char>(1, 63);     // starting with 'S'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 212);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x28)(0x21)(0x38).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x05)(0x27)(0x33)(0x22).convert_to_container<std::vector<unsigned char> >();
        //  BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x70)(0x00)(0x00)(0xac).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }

};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xb3;
        pchMessageStart[1] = 0x76;
        pchMessageStart[2] = 0x66;
        pchMessageStart[3] = 0xca;
        nDefaultPort = 6606;

        consensus.nTargetTimespan = 1 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.height_last_PoW = 200;
        consensus.nCoinbaseMaturity = 15;
        consensus.nMasternodeCountDrift = 4;        // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 43199500 * COIN;
        consensus.height_start_ZC = 201576;
        consensus.ZC_TimeStart = 1501776000;
        consensus.height_start_ZC_SerialRangeCheck = 1;

        genesis = CreateGenesisBlock(1515616140, 79855, 0x1e0ffff0, 1, 43199500 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(hashGenesisBlock == uint256("0x000007cff63ef602a51bf074e384b3516f0dd202f14d52f7c8c9b1af9423ab2e"));
        printf("TestNet  Genesis Hash=: =======>%s\n", genesis.GetHash().ToString().c_str());
        
        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("nodes-test.oasis.pw", "nodes-test.oasis.pw")); // Primary DNS Seeder
        vSeeds.push_back(CDNSSeedData("oasis-test.nodes.gyservers.com", "oasis-test.nodes.gyservers.com")); // Secondary DNS Seeder
        vSeeds.push_back(CDNSSeedData("oasis-test.seeds.mn.zone", "oasis-test.seeds.mn.zone")); // Third party DNS Seeder
        vSeeds.push_back(CDNSSeedData("oasis-test.mnseeds.com", "oasis-test.mnseeds.com")); // Third party DNS Seeder

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet oasis addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet oasis script addresses start with '8' or '9'
        base58Prefixes[STAKING_ADDRESS] = std::vector<unsigned char>(1, 73);     // starting with 'W'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet oasis BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet oasis BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet oasis BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

         // spork keys
        consensus.strSporkPubKey = "044e3bfa8d1a0f0807dfd6a85d18ad39e4df40b3b0c7fb1c46f4840805dbe0c810c6cfd2e56f7df41966433d2072aca2115e0dae56387a199d8d2aa69b52398436";
        consensus.strObfuscationPoolDummyAddress = "xp87cG8UEQgzs1Bk67Yk884C7pnQfAeo7q";
        consensus.nBudgetFeeConfirmations = 3;      // (only 8-blocks window for finalization on testnet)

        //========================= pre oasis leap testnet params end with the last variable above this line. ========================//

// height based activations
        consensus.height_last_ZC_AccumCheckpoint = 500;
        consensus.height_start_BIP65 = 500;
        consensus.height_start_MessSignaturesV2 = 500;      // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_StakeModifierNewSelection = 210;
        consensus.height_start_StakeModifierV2 = 500;
        consensus.height_start_TimeProtoV2 = 500;           // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_ZC_PublicSpends = 500;
        consensus.height_start_ZC_SerialsV2 = 500;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // oasis starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 144;         // approx 10 cycles per day
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nPoolMaxTransactions = 2;
        consensus.nProposalEstablishmentTime = 60 * 5;  // at least 5 min old to make it into a budget
        consensus.nStakeMinAge = 60 * 60;
        consensus.nStakeMinDepth = 180;
        consensus.nTargetTimespanV2 = 1 * 60;
        consensus.nTimeSlotLength = 15;

        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 20;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 200;

    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x69;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0x7e;
        pchMessageStart[3] = 0xac;

        consensus.nTargetTimespan = 24 * 60 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.powLimit   = ~UINT256_ZERO >> 1;

        genesis = CreateGenesisBlock(1515524400, 732084, 0x1e0ffff0, 1, 0 * COIN);
        nDefaultPort = 51436;
        consensus.hashGenesisBlock = genesis.GetHash();
        printf("Regression Genesis Hash=: =======>%s\n", genesis.GetHash().ToString().c_str());
         //assert(hashGenesisBlock == uint256("0x000008415bdca132b70cf161ecc548e5d0150fd6634a381ee2e99bb8bb77dbb3"));

        
        consensus.nTargetTimespanV2 = 30 * 60;
        
        consensus.nTimeSlotLength = 15;
        

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        consensus.fPowAllowMinDifficultyBlocks = true;

        //========================= pre oasis leap regtest params end with the last variable above this line. ========================//

         consensus.posLimitV1 = ~UINT256_ZERO >> 24;
         consensus.posLimitV2 = ~UINT256_ZERO >> 20;
         consensus.nBudgetCycleBlocks = 144;         // approx 10 cycles per day
         consensus.nBudgetFeeConfirmations = 3;      // (only 8-blocks window for finalization on regtest)
         consensus.nCoinbaseMaturity = 100;
         consensus.nFutureTimeDriftPoW = 7200;
         consensus.nFutureTimeDriftPoS = 180;
         consensus.nMasternodeCountDrift = 4;        // num of MN we allow the see-saw payments to be off by
         consensus.nMaxMoneyOut = 300000 * COIN;
         consensus.nPoolMaxTransactions = 2;
         consensus.nProposalEstablishmentTime = 60 * 5;  // at least 5 min old to make it into a budget
         consensus.nStakeMinAge = 0;
         consensus.nStakeMinDepth = 2;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 51478;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
