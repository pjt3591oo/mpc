import pkg from 'elliptic';
const { ec: EC } = pkg;

import crypto from 'crypto';

const ec = new EC('secp256k1');

const N_PARTICIPANTS = 5; // 총 참여자 수 (n)
const THRESHOLD = 3;      // 임계값 (t), t명의 참여자가 모여야 (이론적으로) 키 복원 또는 서명 가능

class Participant {
    constructor(id) {
        this.id = id;
        this.secretPolynomialCoeffs = [];
        this.receivedSharesFromOthers = {};
        this.finalSecretShare = null;     
        this.publicKeyShare = null;       
    }

    generateSecretPolynomial() {
        for (let i = 0; i < THRESHOLD; i++) {
            const randomCoeff = BigInt('0x' + crypto.randomBytes(16).toString('hex')); 
            this.secretPolynomialCoeffs.push(randomCoeff);
        }
        this.publicKeyShare = ec.g.mul(this.secretPolynomialCoeffs[0].toString(16));
        
        console.log(`참여자 ${this.id}: 비밀 다항식 생성 완료, 공개키 조각 게시 (첫번째 계수의 g배)`);
    }

    evaluatePolynomial(x) {
        let result = 0n;
        for (let i = 0; i < this.secretPolynomialCoeffs.length; i++) {
            result += this.secretPolynomialCoeffs[i] * (BigInt(x) ** BigInt(i));
        }

        return result;
    }

    calculateAndDistributeShares(allParticipants) {
        console.log(`참여자 ${this.id}: 다른 참여자들을 위한 조각 계산 및 (가상) 전달`);
        for (const otherParticipant of allParticipants) {
            const shareForOther = this.evaluatePolynomial(otherParticipant.id);
            otherParticipant.receiveShare(this.id, shareForOther);
        }
    }

    receiveShare(fromParticipantId, shareValue) {
        this.receivedSharesFromOthers[fromParticipantId] = shareValue;
    }

    calculateFinalSecretShare() {
        let sumOfReceivedShares = 0n;
        for (const fromId in this.receivedSharesFromOthers) {
            sumOfReceivedShares += this.receivedSharesFromOthers[fromId];
        }

        this.finalSecretShare = sumOfReceivedShares;
        console.log(`참여자 ${this.id}: 최종 개인키 조각 s_${this.id} 계산 완료 = ${this.finalSecretShare.toString().slice(0,10)}...`);
    }
}

async function simulateDKG() {
    console.log("--- DKG (분산 키 생성) 시뮬레이션 시작 ---");
    console.log(`참여자 수: ${N_PARTICIPANTS}, 임계값: ${THRESHOLD}\n`);

    const participants = [];
    for (let i = 1; i <= N_PARTICIPANTS; i++) {
        participants.push(new Participant(i));
    }

    console.log("--- 1단계: 각 참여자 비밀 다항식 생성 및 공개키 조각 게시 ---");
    for (const p of participants) {
        p.generateSecretPolynomial();
    }
    console.log("");

    console.log("--- 2단계: 각 참여자, 다른 참여자들에게 조각 전달 (VSS 검증 가정) ---");
    for (const p of participants) {
        p.calculateAndDistributeShares(participants);
    }
    console.log("");

    console.log("--- 3단계: 각 참여자 최종 개인키 조각 계산 ---");
    for (const p of participants) {
        p.calculateFinalSecretShare();
    }
    console.log("");


    console.log("--- 4단계: 공동 공개키 계산 ---");
    let combinedPublicKey = participants[0].publicKeyShare;
    for (let i = 1; i < participants.length; i++) {
        combinedPublicKey = combinedPublicKey.add(participants[i].publicKeyShare);
    }
    console.log("공동 공개키 (PK):", combinedPublicKey.encode('hex').slice(0, 20) + "..."); 
    console.log("\n--- DKG 시뮬레이션 종료 ---");

    return { participants, combinedPublicKey };
}

simulateDKG();