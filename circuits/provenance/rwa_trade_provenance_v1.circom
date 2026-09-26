pragma circom 2.2.2;

include "../shared/zk-origin/poseidon.circom";
include "../shared/zk-origin/merkle.circom";
include "circomlib/circuits/bitify.circom";

// ASCII tags encoded as positive big-endian integers. The circuit contains
// numeric constants only; the labels are documentation for the adapter.
function DOMAIN_ASSET_V1() { return 18387490596738609; }      // "ASSETV1"
function DOMAIN_ISSUANCE_META_V1() { return 5283658379176460593; } // "ISSMETA1"
function DOMAIN_ISSUANCE_V1() { return 20639290677876273; }   // "ISSUEV1"
function DOMAIN_FEE_V1() { return 301809882673; }             // "FEEV1"
function DOMAIN_TRADE_A_V1() { return 23734351151715889; }    // "TRDA_V1"
function DOMAIN_TRADE_B_V1() { return 23734351168493105; }    // "TRDB_V1"
function DOMAIN_TRADE_META_V1() { return 23734351353042481; } // "TRDM_V1"
function DOMAIN_TRADE_V1() { return 6075990608753677873; }    // "TRADE_V1"
function ZEC_ASSET_TAG() { return 5915971; }                   // "ZEC"

template RwaTradeProvenanceV1(MERKLE_DEPTH) {
    // Public statement.
    signal input authorizedIssuanceRoot;
    signal input tradeCommitment;

    // Private authorized-issuance witness.
    signal input issuerCommitment;
    signal input offeredAssetHi;
    signal input offeredAssetLo;
    signal input seriesCommitment;
    signal input policyRoot;
    signal input issuanceNonce;
    signal input issuanceMerkleSiblings[MERKLE_DEPTH];
    signal input issuanceMerklePathIndices[MERKLE_DEPTH];

    // Private exact-trade witness.
    signal input offeredAmount;
    signal input requestedAssetHi;
    signal input requestedAssetLo;
    signal input requestedAmount;
    signal input recipientCommitment;
    signal input matcherFeeAmount;
    signal input matcherFeeRecipientCommitment;
    signal input nonce;
    signal input expiry;

    // Lossless external 32-byte encodings use two 128-bit limbs.
    component offeredHiRange = Num2Bits(128);
    component offeredLoRange = Num2Bits(128);
    component requestedHiRange = Num2Bits(128);
    component requestedLoRange = Num2Bits(128);
    offeredHiRange.in <== offeredAssetHi;
    offeredLoRange.in <== offeredAssetLo;
    requestedHiRange.in <== requestedAssetHi;
    requestedLoRange.in <== requestedAssetLo;

    // Numeric trade fields and issuance nonce are unsigned 64-bit values.
    component issuanceNonceRange = Num2Bits(64);
    component offeredAmountRange = Num2Bits(64);
    component requestedAmountRange = Num2Bits(64);
    component matcherFeeAmountRange = Num2Bits(64);
    component nonceRange = Num2Bits(64);
    component expiryRange = Num2Bits(64);
    issuanceNonceRange.in <== issuanceNonce;
    offeredAmountRange.in <== offeredAmount;
    requestedAmountRange.in <== requestedAmount;
    matcherFeeAmountRange.in <== matcherFeeAmount;
    nonceRange.in <== nonce;
    expiryRange.in <== expiry;

    component offeredAssetHasher = PoseidonHash3();
    offeredAssetHasher.in[0] <== DOMAIN_ASSET_V1();
    offeredAssetHasher.in[1] <== offeredAssetHi;
    offeredAssetHasher.in[2] <== offeredAssetLo;

    component issuanceMetaHasher = PoseidonHash4();
    issuanceMetaHasher.in[0] <== DOMAIN_ISSUANCE_META_V1();
    issuanceMetaHasher.in[1] <== seriesCommitment;
    issuanceMetaHasher.in[2] <== policyRoot;
    issuanceMetaHasher.in[3] <== issuanceNonce;

    component issuanceLeafHasher = PoseidonHash4();
    issuanceLeafHasher.in[0] <== DOMAIN_ISSUANCE_V1();
    issuanceLeafHasher.in[1] <== issuerCommitment;
    issuanceLeafHasher.in[2] <== offeredAssetHasher.out;
    issuanceLeafHasher.in[3] <== issuanceMetaHasher.out;

    component issuanceMembership = MerkleProofVerifier(MERKLE_DEPTH);
    issuanceMembership.leaf <== issuanceLeafHasher.out;
    issuanceMembership.root <== authorizedIssuanceRoot;
    for (var i = 0; i < MERKLE_DEPTH; i++) {
        issuanceMembership.pathElements[i] <== issuanceMerkleSiblings[i];
        issuanceMembership.pathIndices[i] <== issuanceMerklePathIndices[i];
    }
    issuanceMembership.valid === 1;

    component requestedAssetHasher = PoseidonHash3();
    requestedAssetHasher.in[0] <== DOMAIN_ASSET_V1();
    requestedAssetHasher.in[1] <== requestedAssetHi;
    requestedAssetHasher.in[2] <== requestedAssetLo;

    component feeHasher = PoseidonHash4();
    feeHasher.in[0] <== DOMAIN_FEE_V1();
    feeHasher.in[1] <== ZEC_ASSET_TAG();
    feeHasher.in[2] <== matcherFeeAmount;
    feeHasher.in[3] <== matcherFeeRecipientCommitment;

    component tradePartAHasher = PoseidonHash4();
    tradePartAHasher.in[0] <== DOMAIN_TRADE_A_V1();
    tradePartAHasher.in[1] <== offeredAssetHasher.out;
    tradePartAHasher.in[2] <== offeredAmount;
    tradePartAHasher.in[3] <== requestedAssetHasher.out;

    component tradePartBHasher = PoseidonHash4();
    tradePartBHasher.in[0] <== DOMAIN_TRADE_B_V1();
    tradePartBHasher.in[1] <== requestedAmount;
    tradePartBHasher.in[2] <== recipientCommitment;
    tradePartBHasher.in[3] <== policyRoot;

    component tradeMetaHasher = PoseidonHash4();
    tradeMetaHasher.in[0] <== DOMAIN_TRADE_META_V1();
    tradeMetaHasher.in[1] <== feeHasher.out;
    tradeMetaHasher.in[2] <== nonce;
    tradeMetaHasher.in[3] <== expiry;

    component tradeHasher = PoseidonHash4();
    tradeHasher.in[0] <== DOMAIN_TRADE_V1();
    tradeHasher.in[1] <== tradePartAHasher.out;
    tradeHasher.in[2] <== tradePartBHasher.out;
    tradeHasher.in[3] <== tradeMetaHasher.out;

    tradeHasher.out === tradeCommitment;
}

component main {public [authorizedIssuanceRoot, tradeCommitment]} = RwaTradeProvenanceV1(3);
