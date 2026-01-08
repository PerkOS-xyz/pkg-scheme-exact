# @perkos/scheme-exact

EIP-3009 TransferWithAuthorization verification utilities for x402 exact scheme payments. Provides signature verification, balance checking, and nonce validation for immediate on-chain token transfers.

## Installation

```bash
npm install @perkos/scheme-exact
```

## Overview

The exact scheme enables immediate on-chain payments using EIP-3009 `transferWithAuthorization`:

1. **Client signs authorization** (EIP-712) for token transfer
2. **Facilitator verifies** signature, balance, and timing
3. **Settlement executes** `transferWithAuthorization` on-chain
4. **Tokens transfer** directly from client to recipient

## Usage

### Basic Verification

```typescript
import { ExactSchemeVerifier } from '@perkos/scheme-exact';
import type { ExactPayload, PaymentRequirements } from '@perkos/scheme-exact';

const verifier = new ExactSchemeVerifier({
  network: 'base',
  rpcUrl: 'https://mainnet.base.org' // optional
});

const payload: ExactPayload = {
  authorization: {
    from: '0x...payer',
    to: '0x...recipient',
    value: '1000000',
    validAfter: '0',
    validBefore: '1735689600',
    nonce: '0x...'
  },
  signature: '0x...'
};

const requirements: PaymentRequirements = {
  scheme: 'exact',
  network: 'base',
  maxAmountRequired: '1000000',
  resource: '/api/service',
  payTo: '0x...recipient',
  maxTimeoutSeconds: 3600,
  asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' // USDC
};

const result = await verifier.verify(payload, requirements);

if (result.isValid) {
  console.log('Valid authorization from:', result.payer);
} else {
  console.error('Invalid:', result.invalidReason);
}
```

### Create Authorization for Signing

```typescript
import {
  generateNonce,
  createAuthorizationMessage,
  createEIP712Domain,
  TRANSFER_WITH_AUTHORIZATION_TYPES
} from '@perkos/scheme-exact';
import { signTypedData } from 'viem/accounts';

// Generate unique nonce
const nonce = generateNonce();

// Create authorization message
const message = createAuthorizationMessage(
  '0x...from',           // payer
  '0x...to',             // recipient
  '1000000',             // value (USDC 6 decimals)
  '0',                   // validAfter (immediately valid)
  Math.floor(Date.now() / 1000) + 3600, // validBefore (1 hour)
  nonce
);

// Create EIP-712 domain for USDC
const domain = createEIP712Domain(
  8453,                  // chainId (Base)
  '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' // USDC address
);

// Sign the authorization (client-side)
const signature = await signTypedData({
  domain,
  types: TRANSFER_WITH_AUTHORIZATION_TYPES,
  primaryType: 'TransferWithAuthorization',
  message,
  privateKey: '0x...'
});
```

### Check Balance

```typescript
const verifier = new ExactSchemeVerifier({
  network: 'base'
});

const hasBalance = await verifier.checkBalance(
  '0x...address',
  '1000000',
  '0x...tokenAddress'
);

if (!hasBalance) {
  console.log('Insufficient balance');
}
```

### Check Nonce State

```typescript
const isUsed = await verifier.checkNonceState(
  '0x...authorizer',
  '0x...nonce',
  '0x...tokenAddress'
);

if (isUsed) {
  console.log('Nonce already used');
}
```

### Parse Signature for Contract Call

```typescript
import { parseSignature } from '@perkos/scheme-exact';

const { v, r, s } = parseSignature('0x...');

// Use with transferWithAuthorization contract call
await tokenContract.write.transferWithAuthorization([
  from, to, value, validAfter, validBefore, nonce, v, r, s
]);
```

## API Reference

### ExactSchemeVerifier

```typescript
class ExactSchemeVerifier {
  constructor(config: ExactSchemeConfig);

  // Verification
  verify(payload: ExactPayload, requirements: PaymentRequirements): Promise<VerifyResponse>;
  validateAuthorization(auth: ExactPayload['authorization'], requirements: PaymentRequirements): boolean;
  recoverSigner(authorization: ExactPayload['authorization'], signature: Hex, tokenAddress: Address): Promise<Address | null>;

  // Balance and nonce checks
  checkBalance(address: Address, amount: string, tokenAddress: Address): Promise<boolean>;
  checkNonceState(authorizer: Address, nonce: Hex, tokenAddress: Address): Promise<boolean>;

  // Getters
  getNetwork(): SupportedNetwork;
  getChainId(): number;
  getEIP712Domain(tokenAddress: Address): EIP712Domain;
}
```

### ExactSchemeConfig

```typescript
interface ExactSchemeConfig {
  network: SupportedNetwork;
  rpcUrl?: string;
  tokenName?: string;    // default: chain-specific USDC name
  tokenVersion?: string; // default: "2"
}
```

### EIP712Domain

```typescript
interface EIP712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: Address;
}
```

### SignatureParts

```typescript
interface SignatureParts {
  v: number;
  r: Hex;
  s: Hex;
}
```

## Utility Functions

### generateNonce

Generate a random bytes32 nonce for authorization.

```typescript
import { generateNonce } from '@perkos/scheme-exact';

const nonce = generateNonce();
// => '0x1234...abcd' (32 bytes hex)
```

### createAuthorizationMessage

Create an authorization message object for EIP-712 signing.

```typescript
import { createAuthorizationMessage } from '@perkos/scheme-exact';

const message = createAuthorizationMessage(
  '0x...from',    // payer address
  '0x...to',      // recipient address
  '1000000',      // value
  '0',            // validAfter
  '1735689600',   // validBefore
  '0x...nonce'    // nonce
);
```

### createEIP712Domain

Create an EIP-712 domain for token signing.

```typescript
import { createEIP712Domain } from '@perkos/scheme-exact';

const domain = createEIP712Domain(
  8453,              // chainId
  '0x...',           // tokenAddress
  'USD Coin',        // optional token name
  '2'                // optional version
);
```

### parseSignature

Parse a signature into v, r, s components for contract calls.

```typescript
import { parseSignature } from '@perkos/scheme-exact';

const { v, r, s } = parseSignature('0x...');
```

### isWithinValidityWindow

Check if current time is within the validity window.

```typescript
import { isWithinValidityWindow } from '@perkos/scheme-exact';

const isValid = isWithinValidityWindow(
  '0',           // validAfter
  '1735689600',  // validBefore
  Date.now() / 1000 // optional timestamp
);
```

## EIP-712 Type Definition

The TransferWithAuthorization type definition used for EIP-712 signing:

```typescript
import {
  TRANSFER_WITH_AUTHORIZATION_TYPES,
  TRANSFER_WITH_AUTHORIZATION_TYPE_DEF
} from '@perkos/scheme-exact';

// TRANSFER_WITH_AUTHORIZATION_TYPE_DEF structure:
[
  { name: "from", type: "address" },
  { name: "to", type: "address" },
  { name: "value", type: "uint256" },
  { name: "validAfter", type: "uint256" },
  { name: "validBefore", type: "uint256" },
  { name: "nonce", type: "bytes32" }
]
```

## Contract ABIs

The package exports ABIs for EIP-3009 token interactions:

```typescript
import {
  ERC20_BALANCE_ABI,
  EIP3009_AUTHORIZATION_STATE_ABI,
  TRANSFER_WITH_AUTHORIZATION_ABI
} from '@perkos/scheme-exact';
```

### Available Functions

| ABI | Function | Description |
|-----|----------|-------------|
| `ERC20_BALANCE_ABI` | `balanceOf(account)` | Get token balance |
| `EIP3009_AUTHORIZATION_STATE_ABI` | `authorizationState(authorizer, nonce)` | Check nonce used |
| `TRANSFER_WITH_AUTHORIZATION_ABI` | `transferWithAuthorization(...)` | Execute transfer |

## USDC Token Names

The package includes standard USDC token names by chain:

```typescript
import { USDC_TOKEN_NAMES } from '@perkos/scheme-exact';

// Chain ID => Token Name
{
  1: "USD Coin",       // Ethereum Mainnet
  8453: "USD Coin",    // Base
  84532: "USDC",       // Base Sepolia
  43114: "USD Coin",   // Avalanche
  43113: "USDC",       // Avalanche Fuji
  137: "USD Coin",     // Polygon
  80002: "USDC",       // Polygon Amoy
  42161: "USD Coin",   // Arbitrum
  421614: "USDC",      // Arbitrum Sepolia
  10: "USD Coin",      // Optimism
  11155420: "USDC",    // Optimism Sepolia
  42220: "USD Coin",   // Celo
  11155111: "USDC",    // Sepolia
}
```

## Verification Flow

The `verify()` method performs these checks in order:

1. **Authorization Validation**: Checks recipient and amount against requirements
2. **Signature Recovery**: Recovers signer using EIP-712 typed data
3. **Signer Verification**: Ensures signer matches authorization `from` address
4. **Balance Check**: Verifies sufficient token balance
5. **Timing Validation**: Checks `validAfter` and `validBefore` windows
6. **Nonce Check**: Verifies nonce not already used on-chain

## Re-exported Types

```typescript
import type {
  ExactPayload,
  VerifyResponse,
  PaymentRequirements,
  Address,
  Hex
} from '@perkos/scheme-exact';

// V2 helper
import { getPaymentAmount } from '@perkos/scheme-exact';
```

## Related Packages

- [@perkos/types-x402](https://www.npmjs.com/package/@perkos/types-x402) - Core x402 types
- [@perkos/util-chains](https://www.npmjs.com/package/@perkos/util-chains) - Chain utilities
- [@perkos/scheme-deferred](https://www.npmjs.com/package/@perkos/scheme-deferred) - Deferred payment scheme
- [@perkos/service-x402](https://www.npmjs.com/package/@perkos/service-x402) - x402 service orchestrator

## License

MIT
