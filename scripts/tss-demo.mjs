/**
 * Simple Threshold Signature Scheme (TSS) Demo
 * 
 * This file demonstrates the use of the TrueThresholdSignature class
 * to create a t-of-n threshold signature scheme, where t out of n
 * parties must collaborate to create a valid signature.
 */

import { TrueThresholdSignature } from '../src/tss.mjs';
import CryptoJS from 'crypto-js';

async function tssDemo() {
  console.log('==============================================');
  console.log('🔐 Threshold Signature Scheme (TSS) Demo');
  console.log('==============================================');
  
  // Initialize a 2-of-3 TSS
  console.log('\n📝 Creating a 2-of-3 threshold setup...');
  const tss = new TrueThresholdSignature(2, 3);
  
  // Generate distributed keys
  console.log('\n🔑 Generating distributed keys...');
  const keyData = await tss.generateDistributedKeys();
  console.log(`- Public key: ${keyData.publicKey.slice(0, 32)}...`);
  console.log(`- Total parties: ${keyData.totalParties}`);
  console.log(`- Threshold: ${keyData.threshold}`);
  
  // Message to sign
  const message = "Transfer 5 BTC to address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
  console.log(`\n📄 Message to sign: "${message}"`);
  
  // Create a session ID
  const sessionId = CryptoJS.SHA256(`session_${Date.now()}`).toString().slice(0, 16);
  console.log(`- Session ID: ${sessionId}`);
  
  // Use the same nonce for all parties (required for TSS)
  const commonNonce = CryptoJS.SHA256(`${sessionId}_common_${Date.now()}`).toString();
  console.log(`- Common nonce: ${commonNonce.slice(0, 16)}...`);
  
  // Generate partial signatures from parties 1 and 2
  console.log('\n🖋️ Generating partial signatures...');
  const parties = [keyData.parties[0], keyData.parties[1]]; // Parties 1 and 2
  const partialSignatures = [];
  
  for (const party of parties) {
    console.log(`- Party ${party.id} generating partial signature...`);
    const partialSig = await tss.generatePartialSignature(message, party, sessionId, commonNonce);
    partialSignatures.push(partialSig);
  }
  
  // Combine the partial signatures
  console.log('\n🔗 Combining partial signatures...');
  const combinedSignature = await tss.combinePartialSignatures(message, partialSignatures);
  console.log(`- Combined signature r: ${combinedSignature.r.slice(0, 16)}...`);
  console.log(`- Combined signature s: ${combinedSignature.s.slice(0, 16)}...`);
  
  // Verify the signature
  console.log('\n✅ Verifying signature...');
  const verificationResult = await tss.verifySignature(combinedSignature, keyData.publicKey);
  console.log(`- Signature verification: ${verificationResult.valid ? 'VALID ✓' : 'INVALID ✗'}`);
  
  if (verificationResult.valid) {
    console.log(`- Verified with public key: ${verificationResult.publicKey.slice(0, 32)}...`);
    console.log(`- Participating parties: ${verificationResult.participants.join(', ')}`);
  } else {
    console.log(`- Verification failed: ${verificationResult.reason}`);
  }
  
  // Security guarantee
  console.log('\n🔒 Security guarantee:');
  console.log(`- ${combinedSignature.securityGuarantee}`);
  
  // Now demonstrate threshold enforcement
  console.log('\n⚠️ Threshold enforcement test:');
  try {
    // Try with just one signature
    const insufficientSigs = [partialSignatures[0]];
    await tss.combinePartialSignatures(message, insufficientSigs);
    console.log('- FAILED: Allowed fewer signatures than threshold!');
  } catch (error) {
    console.log(`- PASSED: ${error.message}`);
  }
  
  console.log('\n==============================================');
  console.log('🎉 TSS Demo Completed Successfully');
  console.log('==============================================');
}

// Run the demo
tssDemo().catch(error => {
  console.error('❌ Demo failed with error:', error);
});
