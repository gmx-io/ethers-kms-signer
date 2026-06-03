import type { Provider } from '@ethersproject/abstract-provider';
import {
	Signer,
	type TypedDataDomain,
	type TypedDataField,
	type TypedDataSigner,
} from '@ethersproject/abstract-signer';
import { getAddress as getChecksumAddress } from '@ethersproject/address';
import type { Bytes } from '@ethersproject/bytes';
import { joinSignature } from '@ethersproject/bytes';
import { _TypedDataEncoder, hashMessage } from '@ethersproject/hash';
import { keccak256 } from '@ethersproject/keccak256';
import { defineReadOnly, resolveProperties } from '@ethersproject/properties';
import {
	serialize,
	type UnsignedTransaction,
} from '@ethersproject/transactions';
import type { TypedData } from 'abitype';
import type {
	Hex,
	SerializeTransactionFn,
	TransactionSerializable,
	TypedDataDefinition,
} from 'viem';
import { concat, hashTypedData, serializeTransaction, toHex } from 'viem';
import type { GcpKmsConfig } from '../types/index.js';
import { calculateRecoveryId } from '../utils/signature.js';
import { GcpKmsCore } from './core.js';

/**
 * GCP KMS-backed signer compatible with ethers.js {@link Signer}.
 *
 * Implements the abstract methods required by `@ethersproject/abstract-signer`
 * and supports provider-based operations (`sendTransaction`, `estimateGas`, etc.)
 * when connected via {@link GcpSigner.connect}.
 *
 * @example
 * ```typescript
 * import { ethers } from 'ethers'
 * import { GcpSigner } from '@gmx-io/ethers-kms-signer'
 *
 * const signer = new GcpSigner({
 *   projectId: 'my-project',
 *   locationId: 'global',
 *   keyRingId: 'my-keyring',
 *   keyId: 'my-key',
 *   keyVersion: '1',
 * })
 *
 * const provider = new ethers.providers.JsonRpcProvider(rpcUrl)
 * const connected = signer.connect(provider)
 * const tx = await connected.sendTransaction({ to, value })
 * ```
 *
 * For viem wallet clients, use {@link toGcpKmsAccount}.
 */
export class GcpSigner extends Signer implements TypedDataSigner {
	private readonly core: GcpKmsCore;
	private readonly config: GcpKmsConfig;

	constructor(config: GcpKmsConfig, provider?: Provider) {
		super();
		this.config = config;
		this.core = new GcpKmsCore(config);
		if (provider) {
			defineReadOnly(this, 'provider', provider);
		}
	}

	async getAddress(): Promise<string> {
		const address = await this.core.getAddress();
		return getChecksumAddress(address);
	}

	connect(provider: Provider): GcpSigner {
		return new GcpSigner(this.config, provider);
	}

	async getPublicKey(): Promise<Uint8Array> {
		return this.core.getPublicKey();
	}

	async signMessage(message: Bytes | string): Promise<string> {
		const digest = hashMessage(message);
		const signature = await this.core.signDigest(digest as Hex);
		return joinSignature(signature);
	}

	async signTransaction(
		transaction: Parameters<Signer['signTransaction']>[0],
	): Promise<string> {
		const tx = await resolveProperties(transaction);
		const address = await this.getAddress();

		if (tx.from != null) {
			if (getChecksumAddress(tx.from) !== address) {
				throw new Error('transaction from address mismatch');
			}
			delete tx.from;
		}

		const unsignedTx = tx as UnsignedTransaction;
		const digest = keccak256(serialize(unsignedTx));
		const signature = await this.core.signDigest(
			digest as Hex,
			unsignedTx.chainId ?? null,
		);
		return serialize(unsignedTx, signature);
	}

	async _signTypedData(
		domain: TypedDataDomain,
		types: Record<string, TypedDataField[]>,
		value: Record<string, unknown>,
	): Promise<string> {
		const populated = await _TypedDataEncoder.resolveNames(
			domain,
			types,
			value,
			async (name: string) => {
				if (this.provider == null) {
					throw new Error('cannot resolve ENS names without a provider');
				}
				const resolved = await this.provider.resolveName(name);
				if (resolved == null) {
					throw new Error(`ENS name does not resolve: ${name}`);
				}
				return resolved;
			},
		);

		const digest = _TypedDataEncoder.hash(
			populated.domain,
			types,
			populated.value,
		);
		const signature = await this.core.signDigest(digest as Hex);
		return joinSignature(signature);
	}

	/**
	 * Signs a viem-serializable transaction (for use with {@link toGcpKmsAccount}).
	 */
	async signViemTransaction(
		transaction: TransactionSerializable,
		{
			serializer = serializeTransaction,
		}: { serializer?: SerializeTransactionFn } = {},
	): Promise<Hex> {
		const { keccak256: viemKeccak256 } = await import('viem');
		const serializedTx = await Promise.resolve(
			serializer({
				...transaction,
				r: undefined,
				s: undefined,
				v: undefined,
			}),
		);
		const hash = viemKeccak256(serializedTx);
		const { r, s } = await this.core.signHash(hash);
		const address = await this.core.getAddress();
		const recoveryId = await calculateRecoveryId(
			hash,
			toHex(r, { size: 32 }),
			toHex(s, { size: 32 }),
			address,
		);
		const chainId = transaction.chainId;
		const v = chainId
			? BigInt(chainId * 2 + 35 + recoveryId)
			: BigInt(27 + recoveryId);

		return Promise.resolve(
			serializer({
				...transaction,
				r: toHex(r, { size: 32 }),
				s: toHex(s, { size: 32 }),
				v,
			}),
		) as Promise<Hex>;
	}

	/**
	 * Signs EIP-712 typed data using viem hashing (for use with {@link toGcpKmsAccount}).
	 */
	async signViemTypedData<
		const TTypedData extends TypedData | Record<string, unknown>,
		TPrimaryType extends keyof TTypedData | 'EIP712Domain' = keyof TTypedData,
	>(typedData: TypedDataDefinition<TTypedData, TPrimaryType>): Promise<Hex> {
		const hash = hashTypedData(typedData);
		const { r, s } = await this.core.signHash(hash);
		const address = await this.core.getAddress();
		const recoveryId = await calculateRecoveryId(
			hash,
			toHex(r, { size: 32 }),
			toHex(s, { size: 32 }),
			address,
		);
		const v = 27 + recoveryId;
		return concat([
			toHex(r, { size: 32 }),
			toHex(s, { size: 32 }),
			toHex(v, { size: 1 }),
		]) as Hex;
	}
}
