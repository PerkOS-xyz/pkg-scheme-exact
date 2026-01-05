/**
 * @perkos/scheme-exact
 * EIP-3009 TransferWithAuthorization verification utilities for x402 exact scheme payments
 */

import {
  createPublicClient,
  http,
  recoverTypedDataAddress,
  type PublicClient,
} from "viem";
import type {
  ExactPayload,
  VerifyResponse,
  PaymentRequirements,
  Address,
  Hex,
} from "@perkos/types-x402";
import {
  getChainById,
  getChainIdFromNetwork,
  getRpcUrl,
  type SupportedNetwork,
} from "@perkos/util-chains";

// ============ EIP-3009 Types ============

export const TRANSFER_WITH_AUTHORIZATION_TYPE_DEF = [
  { name: "from", type: "address" },
  { name: "to", type: "address" },
  { name: "value", type: "uint256" },
  { name: "validAfter", type: "uint256" },
  { name: "validBefore", type: "uint256" },
  { name: "nonce", type: "bytes32" },
] as const;

export interface EIP712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: Address;
}

export interface SignatureParts {
  v: number;
  r: Hex;
  s: Hex;
}

export interface ExactSchemeConfig {
  network: SupportedNetwork;
  rpcUrl?: string;
  tokenName?: string;
  tokenVersion?: string;
}

export interface VerificationResult {
  isValid: boolean;
  invalidReason: string | null;
  payer: Address | null;
  recoveredSigner?: Address | null;
}

// ============ Constants ============

export type TransferWithAuthorizationTypes = {
  TransferWithAuthorization: typeof TRANSFER_WITH_AUTHORIZATION_TYPE_DEF;
};

export const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: TRANSFER_WITH_AUTHORIZATION_TYPE_DEF,
} as const;

// Standard USDC token names by chain
export const USDC_TOKEN_NAMES: Record<number, string> = {
  1: "USD Coin",       // Ethereum Mainnet
  43114: "USD Coin",   // Avalanche
  43113: "USDC",       // Avalanche Fuji
  8453: "USD Coin",    // Base
  84532: "USDC",       // Base Sepolia
  137: "USD Coin",     // Polygon
  80002: "USDC",       // Polygon Amoy
  42161: "USD Coin",   // Arbitrum
  421614: "USDC",      // Arbitrum Sepolia
  10: "USD Coin",      // Optimism
  11155420: "USDC",    // Optimism Sepolia
  42220: "USD Coin",   // Celo
  11155111: "USDC",    // Sepolia
};

// ============ ERC-20 ABIs ============

export const ERC20_BALANCE_ABI = [
  {
    name: "balanceOf",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;

export const EIP3009_AUTHORIZATION_STATE_ABI = [
  {
    name: "authorizationState",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "authorizer", type: "address" },
      { name: "nonce", type: "bytes32" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

export const TRANSFER_WITH_AUTHORIZATION_ABI = [
  {
    name: "transferWithAuthorization",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "from", type: "address" },
      { name: "to", type: "address" },
      { name: "value", type: "uint256" },
      { name: "validAfter", type: "uint256" },
      { name: "validBefore", type: "uint256" },
      { name: "nonce", type: "bytes32" },
      { name: "v", type: "uint8" },
      { name: "r", type: "bytes32" },
      { name: "s", type: "bytes32" },
    ],
    outputs: [],
  },
] as const;

// ============ ExactSchemeVerifier Class ============

export class ExactSchemeVerifier {
  private network: SupportedNetwork;
  private chainId: number;
  private publicClient: PublicClient;
  private tokenName: string;
  private tokenVersion: string;

  constructor(config: ExactSchemeConfig) {
    this.network = config.network;
    this.chainId = getChainIdFromNetwork(config.network) || 1;
    this.tokenName = config.tokenName || USDC_TOKEN_NAMES[this.chainId] || "USD Coin";
    this.tokenVersion = config.tokenVersion || "2";

    const chain = getChainById(this.chainId);
    const rpcUrl = config.rpcUrl || getRpcUrl(this.chainId);

    if (!chain || !rpcUrl) {
      throw new Error(`Unsupported network: ${config.network}`);
    }

    this.publicClient = createPublicClient({
      chain,
      transport: http(rpcUrl),
    });
  }

  /**
   * Verify an exact scheme payment authorization
   */
  async verify(
    payload: ExactPayload,
    requirements: PaymentRequirements
  ): Promise<VerifyResponse> {
    try {
      const { authorization, signature } = payload;

      // 1. Validate basic fields
      if (!this.validateAuthorization(authorization, requirements)) {
        return {
          isValid: false,
          invalidReason: "Authorization fields invalid",
          payer: null,
        };
      }

      // 2. Verify signature and recover signer
      const signer = await this.recoverSigner(
        authorization,
        signature as Hex,
        requirements.asset
      );

      if (!signer) {
        return {
          isValid: false,
          invalidReason: "Invalid signature",
          payer: null,
        };
      }

      // 3. Verify signer matches 'from' address
      if (signer.toLowerCase() !== authorization.from.toLowerCase()) {
        return {
          isValid: false,
          invalidReason: `Signer does not match 'from' address. Recovered: ${signer}, Expected: ${authorization.from}`,
          payer: null,
        };
      }

      // 4. Check token balance
      const hasBalance = await this.checkBalance(
        authorization.from,
        authorization.value,
        requirements.asset
      );

      if (!hasBalance) {
        return {
          isValid: false,
          invalidReason: "Insufficient balance",
          payer: null,
        };
      }

      // 5. Verify timing constraints
      const now = BigInt(Math.floor(Date.now() / 1000));
      const validAfter = BigInt(authorization.validAfter);
      const validBefore = BigInt(authorization.validBefore);

      if (now < validAfter) {
        return {
          isValid: false,
          invalidReason: "Authorization not yet valid",
          payer: null,
        };
      }

      if (now > validBefore) {
        return {
          isValid: false,
          invalidReason: "Authorization expired",
          payer: null,
        };
      }

      // 6. Check if nonce is already used on-chain
      const isNonceUsed = await this.checkNonceState(
        authorization.from,
        authorization.nonce as Hex,
        requirements.asset
      );

      if (isNonceUsed) {
        return {
          isValid: false,
          invalidReason: "Authorization nonce already used or canceled",
          payer: null,
        };
      }

      return {
        isValid: true,
        invalidReason: null,
        payer: authorization.from,
      };
    } catch (error) {
      return {
        isValid: false,
        invalidReason: error instanceof Error ? error.message : "Verification failed",
        payer: null,
      };
    }
  }

  /**
   * Validate authorization fields against requirements
   */
  validateAuthorization(
    auth: ExactPayload["authorization"],
    requirements: PaymentRequirements
  ): boolean {
    // Validate recipient
    if (auth.to.toLowerCase() !== requirements.payTo.toLowerCase()) {
      return false;
    }

    // Validate amount (should not exceed max)
    const value = BigInt(auth.value);
    const maxAmount = BigInt(requirements.maxAmountRequired);
    if (value > maxAmount) {
      return false;
    }

    return true;
  }

  /**
   * Recover signer from EIP-712 typed data signature
   */
  async recoverSigner(
    authorization: ExactPayload["authorization"],
    signature: Hex,
    tokenAddress: Address
  ): Promise<Address | null> {
    try {
      const domain = this.getEIP712Domain(tokenAddress);

      const message = {
        from: authorization.from,
        to: authorization.to,
        value: BigInt(authorization.value),
        validAfter: BigInt(authorization.validAfter),
        validBefore: BigInt(authorization.validBefore),
        nonce: authorization.nonce,
      };

      const recoveredAddress = await recoverTypedDataAddress({
        domain,
        types: TRANSFER_WITH_AUTHORIZATION_TYPES,
        primaryType: "TransferWithAuthorization",
        message,
        signature,
      });

      return recoveredAddress as Address;
    } catch {
      return null;
    }
  }

  /**
   * Get EIP-712 domain for token
   */
  getEIP712Domain(tokenAddress: Address): EIP712Domain {
    return {
      name: this.tokenName,
      version: this.tokenVersion,
      chainId: this.chainId,
      verifyingContract: tokenAddress,
    };
  }

  /**
   * Check if account has sufficient token balance
   */
  async checkBalance(
    address: Address,
    amount: string,
    tokenAddress: Address
  ): Promise<boolean> {
    try {
      const balance = await this.publicClient.readContract({
        address: tokenAddress,
        abi: ERC20_BALANCE_ABI,
        functionName: "balanceOf",
        args: [address],
      });

      return balance >= BigInt(amount);
    } catch {
      return false;
    }
  }

  /**
   * Check if authorization nonce has been used
   */
  async checkNonceState(
    authorizer: Address,
    nonce: Hex,
    tokenAddress: Address
  ): Promise<boolean> {
    try {
      const isUsed = await this.publicClient.readContract({
        address: tokenAddress,
        abi: EIP3009_AUTHORIZATION_STATE_ABI,
        functionName: "authorizationState",
        args: [authorizer, nonce],
      });

      return isUsed as boolean;
    } catch {
      // Token may not support EIP-3009 authorizationState
      return false;
    }
  }

  /**
   * Get network name
   */
  getNetwork(): SupportedNetwork {
    return this.network;
  }

  /**
   * Get chain ID
   */
  getChainId(): number {
    return this.chainId;
  }
}

// ============ Utility Functions ============

/**
 * Parse signature into v, r, s components
 */
export function parseSignature(signature: Hex): SignatureParts {
  const sig = signature.slice(2); // Remove '0x'
  const r = `0x${sig.slice(0, 64)}` as Hex;
  const s = `0x${sig.slice(64, 128)}` as Hex;
  const v = parseInt(sig.slice(128, 130), 16);

  return { v, r, s };
}

/**
 * Create EIP-712 domain for USDC token
 */
export function createEIP712Domain(
  chainId: number,
  tokenAddress: Address,
  tokenName?: string,
  tokenVersion?: string
): EIP712Domain {
  return {
    name: tokenName || USDC_TOKEN_NAMES[chainId] || "USD Coin",
    version: tokenVersion || "2",
    chainId,
    verifyingContract: tokenAddress,
  };
}

/**
 * Generate a random nonce for authorization
 */
export function generateNonce(): Hex {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}` as Hex;
}

/**
 * Check if a timestamp is within validity window
 */
export function isWithinValidityWindow(
  validAfter: bigint | string,
  validBefore: bigint | string,
  timestamp?: number
): boolean {
  const now = BigInt(timestamp || Math.floor(Date.now() / 1000));
  const after = BigInt(validAfter);
  const before = BigInt(validBefore);

  return now >= after && now <= before;
}

/**
 * Create authorization message for signing
 */
export function createAuthorizationMessage(
  from: Address,
  to: Address,
  value: bigint | string,
  validAfter: bigint | string,
  validBefore: bigint | string,
  nonce: Hex
) {
  return {
    from,
    to,
    value: BigInt(value),
    validAfter: BigInt(validAfter),
    validBefore: BigInt(validBefore),
    nonce,
  };
}

// Re-export types
export type { ExactPayload, VerifyResponse, PaymentRequirements, Address, Hex };
