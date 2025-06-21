# MPC - Threshold Signature Scheme Implementation

[한국어 README](./README.md)

This project implements a Threshold Signature Scheme (TSS) based on Elliptic Curve Digital Signature Algorithm (ECDSA) using the secp256k1 curve, providing a cryptographically secure distributed signing mechanism.

## Overview

A Threshold Signature Scheme (TSS) allows a group of n parties to collectively generate a signature, where at least t participants (the threshold) must collaborate to create a valid signature. Key security properties include:

- The private key is never fully reconstructed during the signing process
- The t-of-n threshold requirement is strictly enforced
- The resulting signature can be verified as a standard ECDSA signature

## Project Structure

```
mpc-playground/
├── src/
│   └── tss.mjs          # Main TSS implementation
├── scripts/
│   ├── direct-test.mjs  # Direct ECDSA signature creation and verification test
│   ├── tss-demo.mjs     # TSS functionality demonstration
│   ├── user-tss.mjs     # TSS security test script
│   ├── sss.mjs          # Additional secret sharing implementation
│   └── test-ecdsa.mjs   # ECDSA test
├── tests/
│   ├── tss.en.test.js   # Vitest test script (English)
│   └── tss.ko.test.js   # Vitest test script (Korean)
├── package.json         # Project dependencies
└── README.md            # Project documentation
```

## Technology Stack

### Dependencies

- **elliptic**: For elliptic curve cryptography operations
- **bn.js**: For big number arithmetic
- **crypto-js**: For hash function operations
- **crypto**: For secure random number generation

### Development Dependencies

- **vitest**: Testing framework

## Key Components

### 1. Key Generation and Distribution

Uses polynomial-based threshold scheme to securely distribute the private key:

```javascript
// Create a t-of-n TSS instance
const tss = new TrueThresholdSignature(2, 3); // 2-of-3 example

// Generate distributed keys
const keyData = await tss.generateDistributedKeys();
```

- Uses polynomials to split the key (degree: threshold-1)
- Private key is immediately destroyed after generation
- Each participant holds only their own key share
- Public key is shared with all participants

### 2. Partial Signature Generation

Each participant can independently generate a partial signature using their private key share:

```javascript
// Generate partial signature
const partialSig = await tss.generatePartialSignature(message, party, sessionId, commonNonce);
```

- All participants use the same nonce (k) to ensure consistent R values
- Each participant generates a partial signature using only their key share
- Individual partial signatures cannot create a valid signature alone

### 3. Signature Combination

Combines threshold or more partial signatures to create a complete signature:

```javascript
// Combine partial signatures
const signature = await tss.combinePartialSignatures(message, partialSignatures);
```

- Uses Lagrange interpolation to combine signatures without reconstructing the private key
- Rejects attempts to combine fewer than threshold signatures
- Detects and rejects duplicate signatures
- Rejects signatures from invalid participants
- Normalizes signature according to secp256k1 requirements (s < n/2)

### 4. Signature Verification

Verifies the combined signature using standard ECDSA verification algorithm:

```javascript
// Verify signature
const verificationResult = await tss.verifySignature(signature, publicKey);
```

- Can be verified as a standard ECDSA signature in any blockchain system
- Includes message hash verification
- Combined signature is identical to a single standard ECDSA signature

## Testing and Validation

The project includes various tests to verify the correctness and security of the TSS implementation:

### Automated Tests

Automated tests using Vitest:

```bash
# Run all tests (English tests)
npm test

# Run Korean tests
npm run test:ko

# Run tests in watch mode
npm run test:watch
```

Test files are provided in both English and Korean versions:
- `tss.test.js`: English test cases
- `tss.test.ko.js`: Korean test cases (same tests written in Korean)

### Security Test Scenarios

Validates the following security scenarios:

1. **Exactly Threshold Valid Signatures**: When exactly t participants sign, a valid signature is generated and verified
2. **Fewer Than Threshold Signatures**: With t-1 participants, it's impossible to generate a valid signature
3. **Mixed Invalid Signatures**: Combination fails when invalid signatures are included
4. **More Than Threshold Signatures**: When more than t participants are involved, exactly t signatures are used
5. **Duplicate Signatures**: Duplicate signatures from the same participant are rejected

## Usage Examples

### Basic Usage

```javascript
import { TrueThresholdSignature } from './src/tss.mjs';

// 1. Create a 2-of-3 TSS instance
const tss = new TrueThresholdSignature(2, 3);

// 2. Generate distributed keys
const keyData = await tss.generateDistributedKeys();
const { publicKey, parties } = keyData;

// 3. Generate partial signatures (each participant)
const message = "Hello, TSS!";
const sessionId = "unique-session-id";
const commonNonce = "common-nonce-for-all-parties";

const partialSig1 = await tss.generatePartialSignature(
  message, parties[0], sessionId, commonNonce
);
const partialSig2 = await tss.generatePartialSignature(
  message, parties[1], sessionId, commonNonce
);

// 4. Combine signatures
const signature = await tss.combinePartialSignatures(
  message, [partialSig1, partialSig2]
);

// 5. Verify signature
const verification = await tss.verifySignature(signature, publicKey);
console.log("Signature verification result:", verification.valid);
```

### Running Demos

```bash
# Run the TSS demo
node tss-demo.mjs

# Run security tests
node user-tss.mjs
```

## Contributing

If you'd like to contribute to this project:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

ISC License - See the LICENSE file for details.
