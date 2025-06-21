import { describe, it, expect, beforeAll } from 'vitest';
import { TrueThresholdSignature } from '../src/tss.mjs';
import CryptoJS from 'crypto-js';

// Test utilities for consistent test environment
const createTestEnvironment = async () => {
  // Main TSS (3-of-5)
  const tss = new TrueThresholdSignature(3, 5);
  const keyPair = await tss.generateDistributedKeys();
  
  // Invalid TSS (2-of-2) for testing invalid signatures
  const falseTss = new TrueThresholdSignature(2, 2);
  const falseKeyPair = await falseTss.generateDistributedKeys();
  
  // Common message and session data
  const message = "data to be signed";
  const sessionId = CryptoJS.SHA256(`session_${Date.now()}`).toString().slice(0, 16);
  const commonNonce = CryptoJS.SHA256(`${sessionId}_common_${Date.now()}`).toString();
  
  // Generate all valid signatures
  const validSigs = [];
  for (let i = 0; i < 5; i++) {
    const partialSig = await tss.generatePartialSignature(
      message, keyPair.parties[i], sessionId, commonNonce
    );
    validSigs.push(partialSig);
  }
  
  // Generate an invalid signature from a different key set
  const invalidSig = await falseTss.generatePartialSignature(
    message, falseKeyPair.parties[0], sessionId, commonNonce
  );
  
  return {
    tss,
    keyPair,
    falseTss,
    falseKeyPair,
    message,
    sessionId,
    commonNonce,
    validSigs,
    invalidSig
  };
};

describe('Threshold Signature Scheme (TSS) Tests', () => {
  let env;
  
  beforeAll(async () => {
    env = await createTestEnvironment();
  });
  
  describe('Key Generation', () => {
    it('should generate distributed keys correctly', () => {
      expect(env.keyPair).toBeDefined();
      expect(env.keyPair.publicKey).toBeDefined();
      expect(env.keyPair.parties.length).toBe(5);
      expect(env.keyPair.threshold).toBe(3);
    });
  });
  
  describe('Signature Combination and Verification', () => {
    it('should successfully combine and verify exact threshold (t) signatures', async () => {
      const testSigs = env.validSigs.slice(0, 3); // Parties 1,2,3
      
      const finalSig = await env.tss.combinePartialSignatures(env.message, testSigs);
      expect(finalSig).toBeDefined();
      expect(finalSig.r).toBeDefined();
      expect(finalSig.s).toBeDefined();
      
      const verify = await env.tss.verifySignature(finalSig, env.keyPair.publicKey);
      expect(verify.valid).toBe(true);
    });
    
    it('should reject less than threshold signatures', async () => {
      const testSigs = env.validSigs.slice(0, 2); // Only parties 1,2
      
      await expect(
        env.tss.combinePartialSignatures(env.message, testSigs)
      ).rejects.toThrow(/At least 3 partial signatures are required/);
    });
    
    it('should reject combination with invalid signatures from different key sets', async () => {
      const testSigs = [env.validSigs[0], env.validSigs[1], env.invalidSig];
      
      await expect(
        env.tss.combinePartialSignatures(env.message, testSigs)
      ).rejects.toThrow();
    });
    
    it('should successfully use only threshold signatures when more are provided', async () => {
      const testSigs = env.validSigs.slice(0, 4); // Parties 1,2,3,4
      
      const finalSig = await env.tss.combinePartialSignatures(env.message, testSigs);
      const verify = await env.tss.verifySignature(finalSig, env.keyPair.publicKey);
      
      expect(verify.valid).toBe(true);
      expect(finalSig.participatingParties.length).toBeLessThanOrEqual(3);
    });
    
    it('should reject duplicate signatures', async () => {
      const testSigs = [env.validSigs[0], env.validSigs[0], env.validSigs[0]];
      
      await expect(
        env.tss.combinePartialSignatures(env.message, testSigs)
      ).rejects.toThrow(/Need 3 unique party signatures/);
    });
  });
  
  describe('Security Validation', () => {
    it('should pass security validation', () => {
      expect(env.tss.hasOwnProperty('reconstructPrivateKey')).toBe(false);
      
      expect(typeof env.tss.generatePartialSignature).toBe('function');
      
      // Ensure threshold is properly enforced
      expect(env.tss.threshold).toBeGreaterThanOrEqual(2);
    });
  });
});
