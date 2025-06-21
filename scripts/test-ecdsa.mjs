// ECDSA 검증 테스트 파일
import pkg from 'elliptic';
const { ec: EC } = pkg;
import BN from 'bn.js';
import CryptoJS from 'crypto-js';

// 타원곡선 초기화
const ec = new EC('secp256k1');

// 1. 간단한 ECDSA 키 생성 및 서명 검증 테스트
function testBasicECDSA() {
  console.log("=== 기본 ECDSA 테스트 ===");
  
  // 새 키페어 생성
  const keyPair = ec.genKeyPair();
  const privateKey = keyPair.getPrivate().toString(16);
  const publicKey = keyPair.getPublic().encode('hex');
  
  console.log(`- 개인키: ${privateKey.slice(0, 8)}...`);
  console.log(`- 공개키: ${publicKey.slice(0, 16)}...`);
  
  // 메시지 해시 생성
  const message = "Test message";
  const messageHash = CryptoJS.SHA256(message).toString();
  console.log(`- 메시지 해시: ${messageHash.slice(0, 16)}...`);
  
  // 서명 생성
  const msgHashBN = new BN(messageHash, 16);
  const signature = keyPair.sign(msgHashBN.toArray());
  console.log(`- 서명 생성됨: r=${signature.r.toString(16).slice(0, 8)}..., s=${signature.s.toString(16).slice(0, 8)}...`);
  
  // 서명 검증
  const verified = keyPair.verify(msgHashBN.toArray(), signature);
  console.log(`- 검증 결과: ${verified ? '성공 ✅' : '실패 ❌'}`);
  
  // 서명을 다른 형식으로 변환하여 검증
  const pubKey = ec.keyFromPublic(publicKey, 'hex');
  const verified2 = pubKey.verify(msgHashBN.toArray(), {
    r: signature.r.toString(16),
    s: signature.s.toString(16)
  });
  console.log(`- 문자열 변환 후 검증: ${verified2 ? '성공 ✅' : '실패 ❌'}`);
  
  return verified && verified2;
}

// 2. 간단한 Threshold Signature 테스트 (2-of-3)
function testSimpleThresholdSignature() {
  console.log("\n=== 간단한 Threshold Signature 테스트 (2-of-3) ===");
  
  // 마스터 개인키 생성
  const masterKeyPair = ec.genKeyPair();
  const masterPrivateKey = masterKeyPair.getPrivate();
  const masterPublicKey = masterKeyPair.getPublic().encode('hex');
  console.log(`- 마스터 공개키: ${masterPublicKey.slice(0, 16)}...`);
  
  // 간단한 (2,3) Shamir's Secret Sharing
  // 다항식: f(x) = masterPrivateKey + a1*x
  const a1 = new BN(ec.genKeyPair().getPrivate().toString(16), 16).umod(ec.n);
  console.log(`- 다항식 계수 a1: ${a1.toString(16).slice(0, 8)}...`);
  
  // 각 참여자에게 비밀 공유 생성
  const shares = [];
  for (let i = 1; i <= 3; i++) {
    const x = new BN(i);
    // f(x) = masterPrivateKey + a1*x
    const share = masterPrivateKey.add(a1.mul(x)).umod(ec.n);
    shares.push({ id: i, value: share });
    console.log(`- 파티 ${i}의 비밀 공유: ${share.toString(16).slice(0, 8)}...`);
  }
  
  // 메시지 해시 생성
  const message = "Test threshold signature";
  const messageHash = CryptoJS.SHA256(message).toString();
  const msgHashBN = new BN(messageHash, 16);
  console.log(`- 메시지 해시: ${messageHash.slice(0, 16)}...`);
  
  // 공통 nonce (k) 생성
  const k = new BN(ec.genKeyPair().getPrivate().toString(16), 16).umod(ec.n);
  const kPair = ec.keyFromPrivate(k.toArray());
  const R = kPair.getPublic();
  const r = new BN(R.getX().toString(16), 16).umod(ec.n);
  console.log(`- 공통 nonce R의 x좌표: ${r.toString(16).slice(0, 8)}...`);
  
  // 부분 서명 생성 (파티 1과 파티 2만)
  const partialSignatures = [];
  for (let i = 0; i < 2; i++) {
    const share = shares[i];
    const kInv = k.invm(ec.n);
    const shareValue = share.value;
    const partialS = kInv.mul(msgHashBN.add(r.mul(shareValue))).umod(ec.n);
    partialSignatures.push({ id: share.id, s: partialS });
    console.log(`- 파티 ${share.id}의 부분 서명: ${partialS.toString(16).slice(0, 8)}...`);
  }
  
  // 라그랑주 계수 계산
  const participants = partialSignatures.map(sig => sig.id);
  const lagrangeCoeffs = [];
  
  for (const i of participants) {
    let result = new BN(1);
    for (const j of participants) {
      if (i !== j) {
        // 라그랑주 다항식: L_i(0) = Π(j≠i) (0-j)/(i-j)
        const iVal = new BN(i);
        const jVal = new BN(j);
        // 분자: 0 - j
        const num = ec.n.sub(jVal).umod(ec.n);
        // 분모: i - j
        const den = iVal.sub(jVal).umod(ec.n);
        const denInv = den.invm(ec.n);
        result = result.mul(num).mul(denInv).umod(ec.n);
      }
    }
    lagrangeCoeffs.push({ id: i, value: result });
    console.log(`- 파티 ${i}의 라그랑주 계수: ${result.toString(16)}`);
  }
  
  // 서명 결합
  let s = new BN(0);
  for (let i = 0; i < partialSignatures.length; i++) {
    const sig = partialSignatures[i];
    const coeff = lagrangeCoeffs.find(c => c.id === sig.id).value;
    const partialResult = sig.s.mul(coeff).umod(ec.n);
    s = s.add(partialResult).umod(ec.n);
  }
  console.log(`- 결합된 서명 s: ${s.toString(16).slice(0, 8)}...`);
  
  // 표준 서명 범위로 정규화 (s > n/2이면 s = n - s)
  const halfN = ec.n.shrn(1);
  if (s.gt(halfN)) {
    s = ec.n.sub(s);
    console.log(`- 정규화된 서명 s: ${s.toString(16).slice(0, 8)}...`);
  }
  
  // 최종 서명 생성
  const signature = { r, s };
  
  // 서명 검증
  const pubKey = ec.keyFromPublic(masterPublicKey, 'hex');
  const verified = pubKey.verify(msgHashBN.toArray(), signature);
  console.log(`- 검증 결과: ${verified ? '성공 ✅' : '실패 ❌'}`);
  
  return verified;
}

// 모든 테스트 실행
function runAllTests() {
  const basicTest = testBasicECDSA();
  const thresholdTest = testSimpleThresholdSignature();
  
  console.log("\n=== 테스트 결과 요약 ===");
  console.log(`- 기본 ECDSA: ${basicTest ? '성공 ✅' : '실패 ❌'}`);
  console.log(`- 간단한 TSS: ${thresholdTest ? '성공 ✅' : '실패 ❌'}`);
  
  if (basicTest && thresholdTest) {
    console.log("\n✅ 모든 테스트 통과!");
  } else {
    console.log("\n❌ 일부 테스트 실패!");
  }
}

// 테스트 실행
runAllTests();
