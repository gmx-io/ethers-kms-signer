import { hexlify, hexZeroPad, type SignatureLike } from '@ethersproject/bytes';
import type { Address, Hex } from 'viem';
import { fromHex } from 'viem';
import type { GcpKmsConfig } from '../types/index.js';
import {
	extractPublicKeyFromDer,
	publicKeyToAddress,
} from '../utils/address.js';
import { parseDerSignature } from '../utils/der.js';
import {
	calculateRecoveryId,
	calculateV,
	normalizeS,
	uint8ArrayToBigInt,
} from '../utils/signature.js';
import { GcpClient } from './client.js';

/**
 * Shared GCP KMS signing logic used by {@link GcpSigner}.
 */
export class GcpKmsCore {
	private gcpClient: GcpClient;
	private cachedAddress?: Address;
	private cachedPublicKey?: Uint8Array;

	constructor(config: GcpKmsConfig) {
		this.gcpClient = new GcpClient(config);
	}

	async getPublicKey(): Promise<Uint8Array> {
		if (this.cachedPublicKey) {
			return this.cachedPublicKey;
		}

		const derPublicKey = await this.gcpClient.getPublicKey();
		const publicKey = extractPublicKeyFromDer(derPublicKey);
		this.cachedPublicKey = publicKey;
		return publicKey;
	}

	async getAddress(): Promise<Address> {
		if (this.cachedAddress) {
			return this.cachedAddress;
		}

		const publicKey = await this.getPublicKey();
		const address = publicKeyToAddress(publicKey);
		this.cachedAddress = address;
		return address;
	}

	async signHash(hash: Hex): Promise<{ r: bigint; s: bigint }> {
		const hashBytes = fromHex(hash, 'bytes');
		const derSignature = await this.gcpClient.sign(hashBytes);
		const { r: rBytes, s: sBytes } = parseDerSignature(derSignature);
		const r = uint8ArrayToBigInt(rBytes);
		let s = uint8ArrayToBigInt(sBytes);
		s = normalizeS(s);
		return { r, s };
	}

	async signDigest(
		digest: Hex,
		chainId?: number | null,
	): Promise<SignatureLike> {
		const { r, s } = await this.signHash(digest);
		const address = await this.getAddress();
		const rHex = hexZeroPad(hexlify(r), 32);
		const sHex = hexZeroPad(hexlify(s), 32);
		const recoveryId = await calculateRecoveryId(
			digest,
			rHex as Hex,
			sHex as Hex,
			address,
		);
		const v =
			chainId != null && chainId !== 0
				? Number(calculateV(recoveryId, chainId))
				: Number(calculateV(recoveryId));
		return { r: rHex, s: sHex, v };
	}
}
