// 직접 서명 생성 및 검증 테스트
import pkg from 'elliptic';
const { ec: EC } = pkg;
import BN from 'bn.js';
import CryptoJS from 'crypto-js';
import { randomBytes } from 'crypto';

// 타원곡선 초기화
const ec = new EC('secp256k1');

// 서명 생성 및 검증 함수
function testSignatureVerification() {
  console.log("=== 직접 서명 생성 및 검증 테스트 ===");
  
  // 키 생성
  const privateKeyBytes = randomBytes(32);
  const keyPair = ec.keyFromPrivate(privateKeyBytes);
  const publicKey = keyPair.getPublic().encode('hex');
  
  console.log(`- 공개키: ${publicKey.slice(0, 20)}...`);
  
  // 메시지 해시 생성
  const message = "data to be signed";
  const messageHash = CryptoJS.SHA256(message).toString();
  console.log(`- 메시지 해시: ${messageHash.slice(0, 20)}...`);
  
  // 해시 변환
  const hashBN = new BN(messageHash, 16);
  const hashBytes = Buffer.from(hashBN.toArray());
  console.log(`- 해시 바이트 길이: ${hashBytes.length}`);
  
  // 서명 생성
  const signature = keyPair.sign(hashBytes);
  console.log(`- 서명 r: ${signature.r.toString(16)}`);
  console.log(`- 서명 s: ${signature.s.toString(16)}`);
  
  // BN 객체로 서명 생성
  const pubKey = ec.keyFromPublic(publicKey, 'hex');
  const verify1 = pubKey.verify(hashBytes, signature);
  console.log(`- 검증 결과 (바이트): ${verify1 ? '성공 ✅' : '실패 ❌'}`);
  
  // 다양한 방식으로 검증
  const sigObj = { r: signature.r, s: signature.s };
  const verify2 = pubKey.verify(hashBytes, sigObj);
  console.log(`- 검증 결과 (객체): ${verify2 ? '성공 ✅' : '실패 ❌'}`);
  
  // 해시를 다양한 형식으로 변환하여 검증
  const msgHashHex = messageHash.padStart(64, '0');
  const msgHashBN = new BN(msgHashHex, 16);
  const msgHashArr = msgHashBN.toArray();
  
  const verify3 = pubKey.verify(msgHashArr, sigObj);
  console.log(`- 검증 결과 (배열): ${verify3 ? '성공 ✅' : '실패 ❌'}`);
  
  // 해시 변환 체크
  console.log(`- 해시 hex: ${messageHash}`);
  console.log(`- 해시 바이트: ${Buffer.from(messageHash, 'hex').toString('hex')}`);
  
  return { 
    publicKey, 
    message, 
    messageHash, 
    signature, 
    verify1, 
    verify2, 
    verify3 
  };
}

// TSS 직접 구현 테스트
function testDirectTSS() {
  console.log("\n=== TSS 직접 구현 테스트 ===");
  
  // 키 생성
  const privateKey = new BN(randomBytes(32));
  const publicKey = ec.g.mul(privateKey);
  
  console.log(`- 개인키: ${privateKey.toString(16).slice(0, 8)}...`);
  console.log(`- 공개키: ${publicKey.encode('hex').slice(0, 20)}...`);
  
  // 메시지 해시
  const message = "data to be signed";
  const messageHash = CryptoJS.SHA256(message).toString();
  const msgHashBN = new BN(messageHash, 16);
  
  // 공통 nonce (k) 생성
  const k = new BN(randomBytes(32)).umod(ec.n);
  const R = ec.g.mul(k);
  const r = new BN(R.getX().toString(16), 16).umod(ec.n);
  
  console.log(`- R 점: ${R.encode('hex').slice(0, 20)}...`);
  console.log(`- r 값: ${r.toString(16).slice(0, 8)}...`);
  
  // 정상적인 ECDSA 서명
  const kinv = k.invm(ec.n);
  const s = kinv.mul(msgHashBN.add(r.mul(privateKey))).umod(ec.n);
  
  // 서명 정규화 (s > n/2이면 s = n - s)
  const halfN = ec.n.shrn(1);
  const normalizedS = s.gt(halfN) ? ec.n.sub(s) : s;
  
  console.log(`- 서명 s: ${normalizedS.toString(16).slice(0, 8)}...`);
  
  // 서명 검증
  const pubKeyObj = ec.keyFromPublic(publicKey);
  const sigObj = { r, s: normalizedS };
  
  const verify = pubKeyObj.verify(msgHashBN.toArray(), sigObj);
  console.log(`- 검증 결과: ${verify ? '성공 ✅' : '실패 ❌'}`);
  
  // 다양한 해시 형식으로 검증
  const msgBytes = Buffer.from(messageHash, 'hex');
  const verify2 = pubKeyObj.verify(msgBytes, sigObj);
  console.log(`- 검증 결과 (바이트): ${verify2 ? '성공 ✅' : '실패 ❌'}`);
  
  return {
    publicKey,
    messageHash,
    r,
    s: normalizedS,
    verify
  };
}

// 테스트 실행
const sigResult = testSignatureVerification();
const tssResult = testDirectTSS();

console.log("\n=== 테스트 결과 요약 ===");
console.log(`- 기본 서명 검증: ${sigResult.verify1 ? '성공 ✅' : '실패 ❌'}`);
console.log(`- TSS 직접 구현: ${tssResult.verify ? '성공 ✅' : '실패 ❌'}`);
