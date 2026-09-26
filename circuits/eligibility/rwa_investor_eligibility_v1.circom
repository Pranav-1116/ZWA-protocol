pragma circom 2.2.2;

include "../shared/zk-origin/poseidon.circom";
include "../shared/zk-origin/merkle.circom";
include "../shared/zk-origin/comparators.circom";
include "circomlib/circuits/bitify.circom";

// Phase 0F TradeCommitmentV1 domains. These values and the construction below
// are unchanged from rwa_trade_provenance_v1.circom.
function DOMAIN_ASSET_V1() { return 18387490596738609; }
function DOMAIN_FEE_V1() { return 301809882673; }
function DOMAIN_TRADE_A_V1() { return 23734351151715889; }
function DOMAIN_TRADE_B_V1() { return 23734351168493105; }
function DOMAIN_TRADE_META_V1() { return 23734351353042481; }
function DOMAIN_TRADE_V1() { return 6075990608753677873; }
function ZEC_ASSET_TAG() { return 5915971; }

// Phase 0G domains: "SUBJECT1", "RECEIVR1", "RCPBIND1", "CREDMETA",
// and "ELIGPOL1" encoded as positive big-endian integers.
function DOMAIN_SUBJECT_V1() { return 6004778564925477937; }
function DOMAIN_RECEIVER_V1() { return 5928218449365324337; }
function DOMAIN_RECIPIENT_BINDING_V1() { return 5927669780177634353; }
function DOMAIN_CREDENTIAL_META_V1() { return 4851015908287927361; }
function DOMAIN_ELIGIBILITY_POLICY_V1() { return 4993446657485917233; }

// Phase 1B credential leaf domain: "CRED_V2" as a positive big-endian integer.
//
// The V1 leaf (18949280892933681) committed to no receiver, so any receiver
// satisfied any credential. The V2 leaf additionally commits to the
// authority-approved receiver commitment. A distinct domain keeps the two leaf
// statements unambiguous: a V1 leaf can never be read as a V2 leaf.
function DOMAIN_CREDENTIAL_V2() { return 18949280892933682; }

template RwaInvestorEligibilityV1(CREDENTIAL_DEPTH, POLICY_DEPTH) {
    // The only public values.
    signal input activeCredentialRoot;
    signal input tradeCommitment;

    // Private credential witness.
    signal input subjectSecret;
    signal input credentialAuthorityCommitment;
    signal input investorClass;
    signal input jurisdiction;
    signal input credentialExpiry;
    signal input credentialNonce;
    signal input credentialMerkleSiblings[CREDENTIAL_DEPTH];
    signal input credentialMerklePathIndices[CREDENTIAL_DEPTH];

    // Private policy witness.
    signal input policyRoot;
    signal input allowedInvestorClass;
    signal input allowedJurisdiction;
    signal input policyMerkleSiblings[POLICY_DEPTH];
    signal input policyMerklePathIndices[POLICY_DEPTH];

    // Canonical 43-byte Orchard raw payment address, losslessly split as
    // 16-byte LE, 16-byte LE, and 11-byte LE limbs.
    signal input receiverLimb0;
    signal input receiverLimb1;
    signal input receiverLimb2;

    // Private fields needed to recompute Phase 0F TradeCommitmentV1.
    signal input offeredAssetHi;
    signal input offeredAssetLo;
    signal input offeredAmount;
    signal input requestedAssetHi;
    signal input requestedAssetLo;
    signal input requestedAmount;
    signal input matcherFeeAmount;
    signal input matcherFeeRecipientCommitment;
    signal input nonce;
    signal input expiry;

    component offeredHiRange = Num2Bits(128);
    component offeredLoRange = Num2Bits(128);
    component requestedHiRange = Num2Bits(128);
    component requestedLoRange = Num2Bits(128);
    component receiver0Range = Num2Bits(128);
    component receiver1Range = Num2Bits(128);
    component receiver2Range = Num2Bits(88);
    offeredHiRange.in <== offeredAssetHi;
    offeredLoRange.in <== offeredAssetLo;
    requestedHiRange.in <== requestedAssetHi;
    requestedLoRange.in <== requestedAssetLo;
    receiver0Range.in <== receiverLimb0;
    receiver1Range.in <== receiverLimb1;
    receiver2Range.in <== receiverLimb2;

    component investorClassRange = Num2Bits(8);
    component allowedInvestorClassRange = Num2Bits(8);
    component jurisdictionRange = Num2Bits(16);
    component allowedJurisdictionRange = Num2Bits(16);
    component credentialExpiryRange = Num2Bits(64);
    component credentialNonceRange = Num2Bits(64);
    component offeredAmountRange = Num2Bits(64);
    component requestedAmountRange = Num2Bits(64);
    component matcherFeeAmountRange = Num2Bits(64);
    component nonceRange = Num2Bits(64);
    component expiryRange = Num2Bits(64);
    investorClassRange.in <== investorClass;
    allowedInvestorClassRange.in <== allowedInvestorClass;
    jurisdictionRange.in <== jurisdiction;
    allowedJurisdictionRange.in <== allowedJurisdiction;
    credentialExpiryRange.in <== credentialExpiry;
    credentialNonceRange.in <== credentialNonce;
    offeredAmountRange.in <== offeredAmount;
    requestedAmountRange.in <== requestedAmount;
    matcherFeeAmountRange.in <== matcherFeeAmount;
    nonceRange.in <== nonce;
    expiryRange.in <== expiry;

    // The policy tuple proved by membership must be the credential tuple.
    investorClass === allowedInvestorClass;
    jurisdiction === allowedJurisdiction;

    component subjectHasher = PoseidonHash2();
    subjectHasher.in[0] <== DOMAIN_SUBJECT_V1();
    subjectHasher.in[1] <== subjectSecret;

    // SECURITY (Phase 1B): this single receiver commitment is consumed twice —
    // once by the credential leaf as the authority-approved receiver, and once
    // by the recipient binding that feeds TradeCommitmentV1. Because it is one
    // signal rather than two, a prover cannot present a credential approving
    // receiver A while settling to receiver B: substituting the receiver
    // changes the recomputed leaf and credential Merkle membership fails.
    component receiverHasher = PoseidonHash4();
    receiverHasher.in[0] <== DOMAIN_RECEIVER_V1();
    receiverHasher.in[1] <== receiverLimb0;
    receiverHasher.in[2] <== receiverLimb1;
    receiverHasher.in[3] <== receiverLimb2;

    component credentialMetaHasher = PoseidonHash4();
    credentialMetaHasher.in[0] <== DOMAIN_CREDENTIAL_META_V1();
    credentialMetaHasher.in[1] <== investorClass;
    credentialMetaHasher.in[2] <== jurisdiction;
    credentialMetaHasher.in[3] <== credentialExpiry;

    component credentialLeafHasher = PoseidonHash6();
    credentialLeafHasher.in[0] <== DOMAIN_CREDENTIAL_V2();
    credentialLeafHasher.in[1] <== credentialAuthorityCommitment;
    credentialLeafHasher.in[2] <== subjectHasher.out;
    credentialLeafHasher.in[3] <== credentialMetaHasher.out;
    credentialLeafHasher.in[4] <== credentialNonce;
    credentialLeafHasher.in[5] <== receiverHasher.out;

    component credentialMembership = MerkleProofVerifier(CREDENTIAL_DEPTH);
    credentialMembership.leaf <== credentialLeafHasher.out;
    credentialMembership.root <== activeCredentialRoot;
    for (var c = 0; c < CREDENTIAL_DEPTH; c++) {
        credentialMembership.pathElements[c] <== credentialMerkleSiblings[c];
        credentialMembership.pathIndices[c] <== credentialMerklePathIndices[c];
    }
    credentialMembership.valid === 1;

    component recipientHasher = PoseidonHash3();
    recipientHasher.in[0] <== DOMAIN_RECIPIENT_BINDING_V1();
    recipientHasher.in[1] <== subjectHasher.out;
    recipientHasher.in[2] <== receiverHasher.out;

    component policyLeafHasher = PoseidonHash3();
    policyLeafHasher.in[0] <== DOMAIN_ELIGIBILITY_POLICY_V1();
    policyLeafHasher.in[1] <== allowedInvestorClass;
    policyLeafHasher.in[2] <== allowedJurisdiction;

    component policyMembership = MerkleProofVerifier(POLICY_DEPTH);
    policyMembership.leaf <== policyLeafHasher.out;
    policyMembership.root <== policyRoot;
    for (var p = 0; p < POLICY_DEPTH; p++) {
        policyMembership.pathElements[p] <== policyMerkleSiblings[p];
        policyMembership.pathIndices[p] <== policyMerklePathIndices[p];
    }
    policyMembership.valid === 1;

    component validThroughTrade = ZKGreaterEqThan(64);
    validThroughTrade.in[0] <== credentialExpiry;
    validThroughTrade.in[1] <== expiry;
    validThroughTrade.out === 1;

    // Exact Phase 0F TradeCommitmentV1 construction begins here.
    component offeredAssetHasher = PoseidonHash3();
    offeredAssetHasher.in[0] <== DOMAIN_ASSET_V1();
    offeredAssetHasher.in[1] <== offeredAssetHi;
    offeredAssetHasher.in[2] <== offeredAssetLo;

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
    tradePartBHasher.in[2] <== recipientHasher.out;
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

component main {public [activeCredentialRoot, tradeCommitment]} = RwaInvestorEligibilityV1(3, 3);
