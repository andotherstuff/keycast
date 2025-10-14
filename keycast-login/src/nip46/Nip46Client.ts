// ABOUTME: NIP-46 (Nostr Connect) client implementation for remote signing
// ABOUTME: Handles relay connections, encryption, and JSON-RPC requests to bunker

import { SimplePool, Event as NostrEvent, finalizeEvent, getPublicKey } from 'nostr-tools';
import { encrypt as nip44Encrypt, decrypt as nip44Decrypt } from 'nostr-tools/nip44';
import { encrypt as nip04Encrypt, decrypt as nip04Decrypt } from 'nostr-tools/nip04';

export interface Nip46Config {
  bunkerPubkey: string;  // The bunker's public key
  relay: string;         // Relay URL (wss://relay.damus.io)
  secret: string;        // Connection secret from bunker URL
}

export interface Nip46Request {
  id: string;
  method: string;
  params: any[];
}

export interface Nip46Response {
  id: string;
  result?: any;
  error?: string;
}

export class Nip46Client {
  private pool: SimplePool;
  private bunkerPubkey: string;
  private relay: string;
  private secret: string;
  private clientKeys: { publicKey: string; privateKey: string };
  private pendingRequests: Map<string, {
    resolve: (value: any) => void;
    reject: (error: Error) => void;
  }> = new Map();
  private subscriptionId: string | null = null;

  constructor(config: Nip46Config) {
    this.pool = new SimplePool();
    this.bunkerPubkey = config.bunkerPubkey;
    this.relay = config.relay;
    this.secret = config.secret;

    // Generate ephemeral client keys from secret
    // In a real implementation, you might want to derive this differently
    this.clientKeys = {
      privateKey: config.secret.padEnd(64, '0').substring(0, 64),
      publicKey: '', // Will be set below
    };
    this.clientKeys.publicKey = getPublicKey(this.clientKeys.privateKey);
  }

  async connect(): Promise<void> {
    // Subscribe to responses from the bunker
    this.subscriptionId = this.pool.subscribeMany(
      [this.relay],
      [
        {
          kinds: [24133], // NIP-46 response event kind
          '#p': [this.clientKeys.publicKey],
          authors: [this.bunkerPubkey],
        },
      ],
      {
        onevent: async (event) => {
          await this.handleResponse(event);
        },
        oneose: () => {
          // console.log('NIP-46 subscription established');
        },
      }
    );

    // Send connect request
    await this.sendRequest('connect', [this.clientKeys.publicKey, this.secret]);
  }

  async disconnect(): Promise<void> {
    if (this.subscriptionId) {
      this.pool.close([this.relay]);
      this.subscriptionId = null;
    }
  }

  async signEvent(unsignedEvent: any): Promise<any> {
    const response = await this.sendRequest('sign_event', [unsignedEvent]);
    return response;
  }

  async getPublicKey(): Promise<string> {
    const response = await this.sendRequest('get_public_key', []);
    return response;
  }

  async nip04Encrypt(thirdPartyPubkey: string, plaintext: string): Promise<string> {
    const response = await this.sendRequest('nip04_encrypt', [thirdPartyPubkey, plaintext]);
    return response;
  }

  async nip04Decrypt(thirdPartyPubkey: string, ciphertext: string): Promise<string> {
    const response = await this.sendRequest('nip04_decrypt', [thirdPartyPubkey, ciphertext]);
    return response;
  }

  async nip44Encrypt(thirdPartyPubkey: string, plaintext: string): Promise<string> {
    const response = await this.sendRequest('nip44_encrypt', [thirdPartyPubkey, plaintext]);
    return response;
  }

  async nip44Decrypt(thirdPartyPubkey: string, ciphertext: string): Promise<string> {
    const response = await this.sendRequest('nip44_decrypt', [thirdPartyPubkey, ciphertext]);
    return response;
  }

  private async sendRequest(method: string, params: any[]): Promise<any> {
    const requestId = Math.random().toString(36).substring(7);

    const request: Nip46Request = {
      id: requestId,
      method,
      params,
    };

    // Create promise for response
    const responsePromise = new Promise((resolve, reject) => {
      this.pendingRequests.set(requestId, { resolve, reject });

      // Timeout after 30 seconds
      setTimeout(() => {
        if (this.pendingRequests.has(requestId)) {
          this.pendingRequests.delete(requestId);
          reject(new Error('NIP-46 request timeout'));
        }
      }, 30000);
    });

    // Encrypt request with NIP-44
    const plaintext = JSON.stringify(request);
    const ciphertext = nip44Encrypt(
      plaintext,
      this.clientKeys.privateKey,
      this.bunkerPubkey
    );

    // Create NIP-46 request event
    const requestEvent = finalizeEvent(
      {
        kind: 24133,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['p', this.bunkerPubkey]],
        content: ciphertext,
      },
      this.clientKeys.privateKey
    );

    // Publish to relay
    await this.pool.publish([this.relay], requestEvent);

    return responsePromise;
  }

  private async handleResponse(event: NostrEvent): Promise<void> {
    try {
      // Decrypt response with NIP-44
      const plaintext = nip44Decrypt(
        event.content,
        this.clientKeys.privateKey,
        this.bunkerPubkey
      );

      const response: Nip46Response = JSON.parse(plaintext);

      // Find matching request
      const pending = this.pendingRequests.get(response.id);
      if (!pending) {
        console.warn('Received response for unknown request:', response.id);
        return;
      }

      this.pendingRequests.delete(response.id);

      // Resolve or reject based on response
      if (response.error) {
        pending.reject(new Error(response.error));
      } else {
        pending.resolve(response.result);
      }
    } catch (error) {
      console.error('Failed to handle NIP-46 response:', error);
    }
  }
}
