import { ArgonType, hash } from "argon2-browser"
import { eddsa } from "elliptic";
import keccak256 from "keccak256";

import { EncryptedKey, Keys } from "./interfaces";

class Account {
    private rootKey: Uint8Array;

    /**
     * Generate an account root key
     * @returns {ArrayBuffer}
     */
    generateRootKey(): Uint8Array {
        return window.crypto.getRandomValues(new Uint8Array(32));
    }

    /**
     * Sets an account root key
     * @param rootKey - Account root key
     */
    setRootKey(rootKey: Uint8Array) {
        this.rootKey = rootKey;
    }

    /**
     * Get the account root key stored in memory
     * @returns {ArrayBuffer|Undefined}
     */
    getRootKey(): Uint8Array | undefined {
        if (this.rootKey) {
            return this.rootKey;
        }

        return undefined;
    }

    /**
     * Derive an AES-CBC encryption key
     * @param key 
     * @returns {CryptoKey}
     */
    private async deriveAesEncryptionKey(key: ArrayBuffer): Promise<CryptoKey> {
        const encryptionKey = await window.crypto.subtle.importKey(
            "raw",
            key,
            { name: "AES-CBC" },
            false,
            ["encrypt", "decrypt"]
        );

        return Promise.resolve(encryptionKey);
    }

    /**
     * Return an encrypted object of the account root key
     * @param password 
     * @returns {EncryptedKey}
     */
    async encryptRootKey(password: string): Promise<EncryptedKey> {
        // Check if root key is present in memory
        const rootKey = this.getRootKey();
        if (!rootKey) {
            Promise.reject("Account root key is not set!")
        }

        // Check if password paramater is valid
        if (password.trim().length === 0) {
            Promise.reject("Password parameter cannot be empty!");
        }

        // Generate salt used for password stretching and encryption IV of the root key
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(16));

        // Stretch password into a stronger key
        const stretchedKey = await hash({
            pass: password,
            salt: salt,
            type: ArgonType.Argon2id,
            hashLen: 32
        });

        // Derive an encryption key using our stretched key to encrypt the root key with
        const encryptionKey = await this.deriveAesEncryptionKey(stretchedKey.hash);

        // Encrypt the root key
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: "AES-CBC", iv: iv },
            encryptionKey,
            rootKey!
        )

        // Generate a signature for the encrypted ciphertext
        const keypair = await this.deriveIdentityKeypair();
        const signature = await this.signData(keypair, Buffer.from(ciphertext).toString("hex"));

        const encryptedKey: EncryptedKey = {
            key: Buffer.from(ciphertext).toString("hex"),
            signature: signature,
            iv: Buffer.from(iv).toString("hex"),
            salt: Buffer.from(salt).toString("hex")
        }

        return Promise.resolve(encryptedKey);
    }

    /* Root Key Methods (Keypairs) */

    /**
     * Returns an identity keypair (EdDSA) to sign data
     * @returns {eddsa.KeyPair}
     */
    async deriveIdentityKeypair(): Promise<eddsa.KeyPair> {
        // Check if root key is present in memory
        const rootKey = this.getRootKey();
        if (!rootKey) {
            Promise.reject("Account root key is not set!")
        }

        // Key is constructed by SHA-256 hashing rootKey + keyType
        const keyType = new TextEncoder().encode(Keys.IDENTITY);
        const concatenatedKey = new Uint8Array([...rootKey!, ...keyType]);
        const secretKey = await window.crypto.subtle.digest("SHA-256", concatenatedKey);

        // Derive the identity EdDSA keypair from the secret
        const ed25519 = new eddsa("ed25519");
        const keypair = ed25519.keyFromSecret(Buffer.from(secretKey));

        return Promise.resolve(keypair);
    }

    /**
     * 
     * @param keypair - Account identity keypair
     * @param data - String data to be signed using Keccak256
     * @returns {string} - Hex-encoded signature
     */
    signData(keypair: eddsa.KeyPair, data: string): Promise<string> {
        // Convert the data into bytes and generate a Keccak256 hash of it
        const dataBytes = new TextEncoder().encode(data);
        const dataHash = keccak256(Buffer.from(dataBytes));

        // Generate the signature using keypair provided as parameter
        const signature = keypair.sign(dataHash).toHex().toLowerCase();
        
        return Promise.resolve(signature)
    }
}

export { Account };