import type { OnRpcRequestHandler } from '@metamask/snaps-sdk';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

interface VaultState {
  sk_a_hex: string;
  vault_address: string;
  enclave_qb_hex: string;
  policy: Record<string, unknown>;
  policy_hash: string;
  voucher_c: string;
  created_at: string;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

function deriveEthereumAddress(uncompressedPubHex: string): string {
  const pubBytes = hexToBytes(uncompressedPubHex);
  const hash = keccak_256(pubBytes.slice(1));
  const addrBytes = hash.slice(-20);
  const rawAddr = bytesToHex(addrBytes);

  // EIP-55 checksum
  const addrHash = bytesToHex(keccak_256(new TextEncoder().encode(rawAddr)));
  let checksummed = '0x';
  for (let i = 0; i < rawAddr.length; i++) {
    if (parseInt(addrHash[i], 16) >= 8) {
      checksummed += rawAddr[i].toUpperCase();
    } else {
      checksummed += rawAddr[i].toLowerCase();
    }
  }
  return checksummed;
}

export const onRpcRequest: OnRpcRequestHandler = async ({ origin, request }) => {
  switch (request.method) {
    case 'scafonix_getVault': {
      const state = (await snap.request({
        method: 'snap_manageState',
        params: { operation: 'get' },
      })) as VaultState | null;

      if (!state) {
        return null;
      }

      return {
        vault_address: state.vault_address,
        policy: state.policy,
        policy_hash: state.policy_hash,
        enclave_qb_hex: state.enclave_qb_hex,
        created_at: state.created_at,
      };
    }

    case 'scafonix_createVault': {
      const params = request.params as {
        policy: Record<string, unknown>;
        recovery_password: string;
        inspector_url?: string;
      };

      if (!params || !params.policy || !params.recovery_password) {
        throw new Error('Missing policy or recovery_password in parameters');
      }

      const inspectorUrl = (params.inspector_url || 'https://vault-api.scafonix.com').replace(/\/$/, '');

      // 1. Generate client secret scalar sk_A
      const keypair = secp256k1.keygen();
      const skAHex = bytesToHex(keypair.secretKey);
      const qABytes = secp256k1.getPublicKey(keypair.secretKey, false);
      const qAHex = bytesToHex(qABytes);

      // 2. Perform 2-party DKG with Inspector
      const res = await fetch(`${inspectorUrl}/api/v1/dkg`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          policy: params.policy,
          client_qa_hex: qAHex,
          recovery_password: params.recovery_password,
        }),
      });

      if (!res.ok) {
        const errData = (await res.json().catch(() => ({}))) as { reason?: string; error?: string };
        throw new Error(errData.reason || errData.error || `Inspector rejected DKG (${res.status})`);
      }

      const dkgResult = (await res.json()) as {
        vault_address: string;
        enclave_qb_hex: string;
        voucher_c: string;
        policy_hash: string;
      };

      // 3. Independent client verification of joint public key and EOA address
      const pA = secp256k1.Point.fromHex(qAHex);
      const pB = secp256k1.Point.fromHex(dkgResult.enclave_qb_hex);
      const pJoint = pA.add(pB);
      const jointPubHex = bytesToHex(pJoint.toBytes(false));
      const clientCalculatedAddress = deriveEthereumAddress(jointPubHex);

      if (clientCalculatedAddress.toLowerCase() !== dkgResult.vault_address.toLowerCase()) {
        throw new Error(
          `Security Alert: Server returned address ${dkgResult.vault_address} but client computed ${clientCalculatedAddress}`,
        );
      }

      // 4. Save state securely inside MetaMask encrypted storage
      const vaultState: VaultState = {
        sk_a_hex: skAHex,
        vault_address: dkgResult.vault_address,
        enclave_qb_hex: dkgResult.enclave_qb_hex,
        policy: params.policy,
        policy_hash: dkgResult.policy_hash,
        voucher_c: dkgResult.voucher_c,
        created_at: new Date().toISOString(),
      };

      await snap.request({
        method: 'snap_manageState',
        params: { operation: 'set', newState: vaultState as any },
      });

      // 5. Present MetaMask confirmation dialog
      await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'alert',
          content: {
            type: 'panel',
            children: [
              { type: 'heading', value: 'scafonix Vault Created' },
              {
                type: 'text',
                value: `Your programmable vault address is ${dkgResult.vault_address}. It is a standard EOA with no smart contract deployment cost.`,
              },
              {
                type: 'text',
                value:
                  'CRITICAL: Save your Emergency Recovery Ticket (Share C) now. Neither scafonix nor MetaMask stores this voucher.',
              },
              { type: 'copyable', value: dkgResult.voucher_c },
            ],
          },
        },
      });

      return {
        vault_address: dkgResult.vault_address,
        voucher_c: dkgResult.voucher_c,
        policy_hash: dkgResult.policy_hash,
      };
    }

    case 'scafonix_signTransaction': {
      const state = (await snap.request({
        method: 'snap_manageState',
        params: { operation: 'get' },
      })) as VaultState | null;

      if (!state) {
        throw new Error('No vault configured in this Snap. Please create a vault first.');
      }

      const params = request.params as {
        tx: {
          chain_id: number;
          recipient: string;
          value_wei: number;
          action: string;
          timestamp?: number;
        };
        inspector_url?: string;
      };

      if (!params || !params.tx) {
        throw new Error('Missing transaction object in parameters');
      }

      const inspectorUrl = (params.inspector_url || 'https://vault-api.scafonix.com').replace(/\/$/, '');

      // 1. Prompt user confirmation in MetaMask
      const ethAmount = (params.tx.value_wei / 1e18).toFixed(4);
      const userConfirmed = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: {
            type: 'panel',
            children: [
              { type: 'heading', value: 'Authorize Vault Transaction' },
              { type: 'text', value: `Vault: ${state.vault_address}` },
              { type: 'text', value: `To: ${params.tx.recipient}` },
              { type: 'text', value: `Amount: ${ethAmount} ETH (${params.tx.value_wei} Wei)` },
              { type: 'text', value: `Chain ID: ${params.tx.chain_id}` },
              {
                type: 'text',
                value:
                  'The 2nd Inspector will verify this transaction against your immutable policy before co-signing.',
              },
            ],
          },
        },
      });

      if (!userConfirmed) {
        throw new Error('User rejected the transaction in MetaMask.');
      }

      // 2. Call 2nd Inspector Co-sign API
      const res = await fetch(`${inspectorUrl}/api/v1/cosign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vault_address: state.vault_address,
          tx: {
            chain_id: params.tx.chain_id,
            recipient: params.tx.recipient,
            value_wei: params.tx.value_wei,
            action: params.tx.action || 'web3:TransferETH',
            timestamp: params.tx.timestamp || Math.floor(Date.now() / 1000),
          },
        }),
      });

      if (!res.ok) {
        const errData = (await res.json().catch(() => ({}))) as { reason?: string; error?: string };
        throw new Error(errData.reason || errData.error || `Inspector rejected signature (${res.status})`);
      }

      const cosignResult = (await res.json()) as {
        status: string;
        message: string;
        vault_address: string;
      };

      return {
        status: 'approved',
        vault_address: state.vault_address,
        message: cosignResult.message,
      };
    }

    case 'scafonix_clearVault': {
      await snap.request({
        method: 'snap_manageState',
        params: { operation: 'clear' },
      });
      return { status: 'cleared' };
    }

    default:
      throw new Error(`Method not found: ${request.method}`);
  }
};
