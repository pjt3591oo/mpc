import { TrueThresholdSignature } from "../src/tss.mjs";
import CryptoJS from 'crypto-js';

async function main() {
  console.log("=========================================");
  console.log("👋 TSS 테스트 시작 - 보안 검증 테스트");
  console.log("=========================================");
  
  // Main TSS (3-of-5)
  const tss = new TrueThresholdSignature(3, 5);
  const keyPair = await tss.generateDistributedKeys();
  console.log("🔑 생성된 공개키:", keyPair.publicKey.slice(0, 20) + "...");
  console.log("👥 총 참여자 수:", keyPair.totalParties);
  console.log("🔐 임계값:", keyPair.threshold);
  
  // 별도의 TSS (2-of-2) - 부정 서명에 사용
  const falseTss = new TrueThresholdSignature(2, 2);
  const falseKeyPair = await falseTss.generateDistributedKeys();
  console.log("\n🚨 부정 검증용 별도 TSS (2-of-2) 생성됨");
  
  const message = "data to be signed";
  console.log("\n📝 서명할 메시지:", message);
  
  const sessionId = CryptoJS.SHA256(`session_${Date.now()}`).toString().slice(0, 16);
  console.log("🆔 세션 ID:", sessionId);
  
  // 모든 테스트에서 동일한 nonce 사용
  const commonNonce = CryptoJS.SHA256(`${sessionId}_common_${Date.now()}`).toString();
  console.log("🎲 공통 Nonce:", commonNonce.slice(0, 16) + "...");
  
  // 모든 서명 생성
  console.log("\n🔐 모든 서명 생성 중...");
  const validSigs = [];
  for (let i = 0; i < 5; i++) {
    const partialSig = await tss.generatePartialSignature(message, keyPair.parties[i], sessionId, commonNonce);
    validSigs.push(partialSig);
    console.log(`  ✓ 파티 ${i+1}의 유효한 부분 서명 생성됨`);
  }
  
  // 유효하지 않은 서명 (다른 TSS 키셋에서 생성)
  const invalidSig = await falseTss.generatePartialSignature(message, falseKeyPair.parties[0], sessionId, commonNonce);
  console.log(`  ✓ 유효하지 않은 부분 서명 (다른 키셋) 생성됨`);
  
  // 테스트 1: 정확히 임계값만큼의 유효 서명 (예상: 성공)
  console.log("\n\n테스트 1. 정확히 임계값만큼의 유효 서명 (예상: ✅ 성공)");
  console.log("-----------------------------------------------");
  try {
    const test1Sigs = validSigs.slice(0, 3); // 파티 1,2,3
    console.log(`- 사용된 파티: ${test1Sigs.map(s => s.partyId).join(', ')}`);
    
    const finalSig1 = await tss.combinePartialSignatures(message, test1Sigs);
    console.log("- 서명 결합 성공");
    
    const verify1 = await tss.verifySignature(finalSig1, keyPair.publicKey);
    console.log(`- 검증 결과: ${verify1.valid ? '✅ 유효' : '❌ 유효하지 않음'}`);
    if (!verify1.valid && verify1.reason) console.log(`- 실패 이유: ${verify1.reason}`);
  } catch (error) {
    console.log(`- ❌ 오류 발생: ${error.message}`);
  }
  
  // 테스트 2: 임계값 미만의 서명 (예상: 실패)
  console.log("\n\n테스트 2. 임계값보다 적은 서명 (예상: ❌ 실패)");
  console.log("-----------------------------------------------");
  try {
    const test2Sigs = validSigs.slice(0, 2); // 파티 1,2만
    console.log(`- 사용된 파티: ${test2Sigs.map(s => s.partyId).join(', ')}`);
    
    const finalSig2 = await tss.combinePartialSignatures(message, test2Sigs);
    console.log("- 서명 결합 성공 (예상치 못함)");
    
    const verify2 = await tss.verifySignature(finalSig2, keyPair.publicKey);
    console.log(`- 검증 결과: ${verify2.valid ? '✅ 유효 (예상치 못함)' : '❌ 유효하지 않음 (예상대로)'}`);
    if (!verify2.valid && verify2.reason) console.log(`- 실패 이유: ${verify2.reason}`);
  } catch (error) {
    console.log(`- ✅ 예상된 오류 발생: ${error.message}`);
  }
  
  // 테스트 3: 일부 유효 + 유효하지 않은 서명 혼합 (예상: 실패)
  console.log("\n\n테스트 3. 유효하지 않은 서명 포함 (예상: ❌ 실패)");
  console.log("-----------------------------------------------");
  try {
    console.log(invalidSig)
    console.log(validSigs[0])
    console.log(validSigs[1])

    const test3Sigs = [validSigs[0], validSigs[1], invalidSig ]; // 파티 1,2 + 유효하지 않은 서명
    console.log(`- 사용된 파티: ${validSigs.slice(0, 2).map(s => s.partyId).join(', ')} + 유효하지 않은 파티`);
    
    const finalSig3 = await tss.combinePartialSignatures(message, test3Sigs);
    console.log("- 서명 결합 성공 (예상치 못함)");
    
    const verify3 = await tss.verifySignature(finalSig3, keyPair.publicKey);
    console.log(`- 검증 결과: ${verify3.valid ? '✅ 유효 (예상치 못함)' : '❌ 유효하지 않음 (예상대로)'}`);
    if (!verify3.valid && verify3.reason) console.log(`- 실패 이유: ${verify3.reason}`);
  } catch (error) {
    console.log(`- ✅ 예상된 오류 발생: ${error.message}`);
  }
  
  // 테스트 4: 임계값 초과 유효 서명 (예상: 성공, 임계값만큼만 사용)
  console.log("\n\n테스트 4. 임계값 초과 유효 서명 (예상: ✅ 성공, 첫 3개만 사용)");
  console.log("-----------------------------------------------");
  try {
    const test4Sigs = validSigs.slice(0, 4); // 파티 1,2,3,4
    console.log(`- 사용된 파티: ${test4Sigs.map(s => s.partyId).join(', ')}`);
    
    const finalSig4 = await tss.combinePartialSignatures(message, test4Sigs);
    console.log("- 서명 결합 성공");
    
    const verify4 = await tss.verifySignature(finalSig4, keyPair.publicKey);
    console.log(`- 검증 결과: ${verify4.valid ? '✅ 유효' : '❌ 유효하지 않음'}`);
    console.log(verify4)
    if (!verify4.valid && verify4.reason) console.log(`- 실패 이유: ${verify4.reason}`);
  } catch (error) {
    console.log(`- ❌ 오류 발생: ${error.message}`);
  }
  
  // 테스트 5: 임계값 채우기 위해 중복 서명 사용 (예상: 실패)
  console.log("\n\n테스트 5.중복 서명 사용 (예상: ❌ 실패)");
  console.log("-----------------------------------------------");
  try {
    const test5Sigs = [validSigs[0], validSigs[0], validSigs[0]]; // 파티 1 서명 3개 중복
    console.log(`- 사용된 파티: ${test5Sigs.map(s => s.partyId).join(', ')} (중복)`);
    
    const finalSig5 = await tss.combinePartialSignatures(message, test5Sigs);
    console.log("- 서명 결합 성공 (예상치 못함)");
    
    const verify5 = await tss.verifySignature(finalSig5, keyPair.publicKey);
    console.log(`- 검증 결과: ${verify5.valid ? '✅ 유효 (예상치 못함)' : '❌ 유효하지 않음 (예상대로)'}`);
    if (!verify5.valid && verify5.reason) console.log(`- 실패 이유: ${verify5.reason}`);
  } catch (error) {
    console.log(`- ✅ 예상된 오류 발생: ${error.message}`);
  }
  
  console.log("\n=========================================");
  console.log("🏁 TSS 보안 테스트 완료");
  console.log("=========================================");
}

main()