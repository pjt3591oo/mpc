# MPC - 임계값 서명 구현 (Threshold Signature Scheme)

[English README](./README.en.md)

이 프로젝트는 타원곡선 암호화(ECDSA)를 기반으로 한 임계값 서명 방식(TSS, Threshold Signature Scheme)을 구현한 것입니다. secp256k1 타원곡선을 사용하여 암호학적으로 안전한 분산 서명 체계를 제공합니다.

## 개요

임계값 서명 방식(TSS)은 n명의 참여자 중 최소 t명(임계값)이 참여해야만 유효한 서명을 생성할 수 있게 하는 암호화 기법입니다. 이 구현의 핵심 보안 특성은 다음과 같습니다:

- 개인키가 서명 과정에서 절대 완전히 복원되지 않음
- t-of-n 임계값 요구사항이 엄격하게 적용됨
- 서명은 단일 표준 ECDSA 서명으로 검증 가능

## 디렉토리 구조

```
mpc-playground/
├── src/
│   └── tss.mjs          # 주요 TSS 구현 코드
├── scripts/
│   ├── direct-test.mjs  # 직접 ECDSA 서명 생성 및 검증 테스트
│   ├── tss-demo.mjs     # TSS 기능 데모
│   ├── user-tss.mjs     # TSS 보안 테스트 스크립트
│   ├── sss.mjs          # 추가 비밀 공유 구현
│   └── test-ecdsa.mjs   # ECDSA 테스트
├── tests/
│   ├── tss.en.test.js   # Vitest 테스트 스크립트 (영문)
│   └── tss.ko.test.js   # Vitest 테스트 스크립트 (한글)
├── package.json         # 프로젝트 의존성 정보
└── README.md            # 프로젝트 문서
```

## 기술 스택

### 의존성

- **elliptic**: 타원곡선 암호화 연산
- **bn.js**: 큰 수의 산술 연산
- **crypto-js**: 해시 함수 연산
- **crypto**: 안전한 난수 생성

### 개발 의존성

- **vitest**: 테스트 프레임워크

## 주요 구성 요소

### 1. 키 생성 및 분배

다항식 기반 임계값 방식을 사용하여 개인키를 안전하게 분배합니다:

```javascript
// t-of-n TSS 인스턴스 생성
const tss = new TrueThresholdSignature(2, 3); // 2-of-3 예시

// 분산 키 생성
const keyData = await tss.generateDistributedKeys();
```

- 다항식을 사용하여 키를 분할 (차수: 임계값-1)
- 개인키는 생성 후 메모리에서 즉시 제거
- 각 참여자는 자신의 키 조각만 보유
- 공개키는 모든 참여자가 공유

### 2. 부분 서명 생성

각 참여자는 자신의 개인키 조각을 사용하여 독립적으로 부분 서명을 생성할 수 있습니다:

```javascript
// 부분 서명 생성
const partialSig = await tss.generatePartialSignature(message, party, sessionId, commonNonce);
```

- 모든 참여자는 동일한 nonce(k)를 사용하여 일관된 R 값 보장
- 각 참여자는 자신의 키 조각만으로 부분 서명 생성
- 개별 부분 서명만으로는 유효한 서명을 만들 수 없음

### 3. 서명 결합

임계값 이상의 부분 서명을 결합하여 완전한 서명을 생성합니다:

```javascript
// 부분 서명 결합
const signature = await tss.combinePartialSignatures(message, partialSignatures);
```

- 라그랑주 보간법을 사용하여 개인키 복원 없이 서명 결합
- 임계값 미만의 서명 조합 시도 거부
- 중복 서명 감지 및 거부
- 유효하지 않은 참여자의 서명 거부
- secp256k1 요구사항에 맞게 서명 정규화 (s < n/2)

### 4. 서명 검증

표준 ECDSA 검증 알고리즘을 사용하여 결합된 서명을 검증합니다:

```javascript
// 서명 검증
const verificationResult = await tss.verifySignature(signature, publicKey);
```

- 어떤 블록체인 시스템에서도 표준 ECDSA 서명으로 검증 가능
- 메시지 해시 검증 포함
- 결합된 서명은 단일 표준 ECDSA 서명과 동일

## 테스트 및 검증

프로젝트는 다양한 테스트를 포함하여 TSS 구현의 정확성과 보안성을 검증합니다:

### 자동화 테스트

Vitest를 사용한 자동화 테스트:

```bash
# 모든 테스트 실행 (영문 테스트)
npm test

# 한글 테스트 실행
npm run test:ko

# 개발 모드에서 테스트 실행 (변경 감지)
npm run test:watch
```

테스트 파일은 영문과 한글 두 버전으로 제공됩니다:
- `tss.test.js`: 영문 테스트 케이스
- `tss.test.ko.js`: 한글 테스트 케이스 (동일한 테스트를 한글로 작성)

### 보안 테스트 시나리오

다음과 같은 보안 시나리오를 검증합니다:

1. **정확히 임계값만큼의 유효 서명**: 정확히 t명의 참여자가 서명할 때 유효한 서명이 생성되고 검증됨
2. **임계값 미만의 서명**: t-1명의 참여자로는 유효한 서명을 생성할 수 없음
3. **유효하지 않은 서명 혼합**: 유효하지 않은 서명이 포함된 경우 결합이 실패함
4. **임계값 초과 서명**: t명 이상이 참여할 경우 정확히 t명의 서명만 사용
5. **중복 서명**: 동일한 참여자의 중복 서명은 거부됨

## 사용 예시

### 기본 사용법

```javascript
import { TrueThresholdSignature } from './src/tss.mjs';

// 1. 2-of-3 TSS 인스턴스 생성
const tss = new TrueThresholdSignature(2, 3);

// 2. 분산 키 생성
const keyData = await tss.generateDistributedKeys();
const { publicKey, parties } = keyData;

// 3. 부분 서명 생성 (각 참여자)
const message = "Hello, TSS!";
const sessionId = "unique-session-id";
const commonNonce = "common-nonce-for-all-parties";

const partialSig1 = await tss.generatePartialSignature(
  message, parties[0], sessionId, commonNonce
);
const partialSig2 = await tss.generatePartialSignature(
  message, parties[1], sessionId, commonNonce
);

// 4. 서명 결합
const signature = await tss.combinePartialSignatures(
  message, [partialSig1, partialSig2]
);

// 5. 서명 검증
const verification = await tss.verifySignature(signature, publicKey);
console.log("서명 검증 결과:", verification.valid);
```

### 데모 실행

```bash
# TSS 데모 실행
node tss-demo.mjs

# 보안 테스트 실행
node user-tss.mjs
```

## 기여하기

이 프로젝트에 기여하고 싶으시다면:

1. 이 저장소를 포크하세요
2. 새 기능 브랜치를 만드세요 (`git checkout -b feature/amazing-feature`)
3. 변경사항을 커밋하세요 (`git commit -m 'Add some amazing feature'`)
4. 브랜치를 푸시하세요 (`git push origin feature/amazing-feature`)
5. Pull Request를 제출하세요

## 라이센스

ISC License - 자세한 내용은 LICENSE 파일을 참조하세요.
