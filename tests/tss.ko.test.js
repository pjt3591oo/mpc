import { describe, it, expect, beforeAll } from 'vitest';
import { TrueThresholdSignature } from '../src/tss.mjs';
import CryptoJS from 'crypto-js';

// 테스트 환경 생성 유틸리티
const createTestEnvironment = async () => {
  // 메인 TSS (3-of-5)
  const tss = new TrueThresholdSignature(3, 5);
  const keyPair = await tss.generateDistributedKeys();
  
  // 부정 검증용 TSS (2-of-2)
  const falseTss = new TrueThresholdSignature(2, 2);
  const falseKeyPair = await falseTss.generateDistributedKeys();
  
  // 공통 메시지 및 세션 데이터
  const message = "data to be signed";
  const sessionId = CryptoJS.SHA256(`session_${Date.now()}`).toString().slice(0, 16);
  const commonNonce = CryptoJS.SHA256(`${sessionId}_common_${Date.now()}`).toString();
  
  // 모든 유효한 서명 생성
  const validSigs = [];
  for (let i = 0; i < 5; i++) {
    const partialSig = await tss.generatePartialSignature(
      message, keyPair.parties[i], sessionId, commonNonce
    );
    validSigs.push(partialSig);
  }
  
  // 다른 키셋에서 유효하지 않은 서명 생성
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

describe('TSS(임계값 서명 방식) 테스트', () => {
  let env;
  
  beforeAll(async () => {
    env = await createTestEnvironment();
  });
  
  describe('키 생성', () => {
    it('분산 키를 올바르게 생성해야 함', () => {
      expect(env.keyPair).toBeDefined();
      expect(env.keyPair.publicKey).toBeDefined();
      expect(env.keyPair.parties.length).toBe(5);
      expect(env.keyPair.threshold).toBe(3);
    });
  });
  
  describe('서명 결합 및 검증', () => {
    it('정확히 임계값(t)만큼의 서명을 결합하고 검증할 수 있어야 함', async () => {
      // 테스트 1: 정확히 임계값만큼의 유효 서명
      const testSigs = env.validSigs.slice(0, 3); // 파티 1,2,3
      
      const finalSig = await env.tss.combinePartialSignatures(env.message, testSigs);
      expect(finalSig).toBeDefined();
      expect(finalSig.r).toBeDefined();
      expect(finalSig.s).toBeDefined();
      
      const verify = await env.tss.verifySignature(finalSig, env.keyPair.publicKey);
      expect(verify.valid).toBe(true);
    });
    
    it('임계값보다 적은 서명은 거부해야 함', async () => {
      // 테스트 2: 임계값보다 적은 서명
      const testSigs = env.validSigs.slice(0, 2); // 파티 1,2만
      
      await expect(
        env.tss.combinePartialSignatures(env.message, testSigs)
      ).rejects.toThrow(/At least 3 partial signatures are required/);
    });
    
    it('다른 키셋에서 생성된 유효하지 않은 서명이 포함된 조합을 거부해야 함', async () => {
      // 테스트 3: 유효한 서명과 유효하지 않은 서명 혼합
      const testSigs = [env.validSigs[0], env.validSigs[1], env.invalidSig];
      
      await expect(
        env.tss.combinePartialSignatures(env.message, testSigs)
      ).rejects.toThrow();
    });
    
    it('임계값 이상의 서명이 제공되면 임계값만큼만 사용해야 함', async () => {
      // 테스트 4: 임계값 초과 유효 서명
      const testSigs = env.validSigs.slice(0, 4); // 파티 1,2,3,4
      
      const finalSig = await env.tss.combinePartialSignatures(env.message, testSigs);
      const verify = await env.tss.verifySignature(finalSig, env.keyPair.publicKey);
      
      expect(verify.valid).toBe(true);
      // 임계값만큼의 파티만 사용되었는지 확인
      expect(finalSig.participatingParties.length).toBeLessThanOrEqual(3);
    });
    
    it('중복 서명을 거부해야 함', async () => {
      // 테스트 5: 중복 서명
      const testSigs = [env.validSigs[0], env.validSigs[0], env.validSigs[0]];
      
      await expect(
        env.tss.combinePartialSignatures(env.message, testSigs)
      ).rejects.toThrow(/Need 3 unique party signatures/);
    });
  });
  
  describe('보안 검증', () => {
    it('보안 검증을 통과해야 함', () => {
      // 개인키 복원 기능이 노출되지 않는지 검증
      expect(env.tss.hasOwnProperty('reconstructPrivateKey')).toBe(false);
      
      // 부분 서명 생성 기능이 구현되어 있는지 확인
      expect(typeof env.tss.generatePartialSignature).toBe('function');
      
      // 임계값이 적절하게 설정되어 있는지 확인
      expect(env.tss.threshold).toBeGreaterThanOrEqual(2);
    });
  });
});
