import { ArgonType, hash } from "argon2-browser"
import keccak256 from "keccak256";
import { eddsa } from "elliptic";

const ed25519 = new eddsa("ed25519");

import { EncryptedAccount, EncryptedKey, EphemeralToken, Keys } from "./interfaces";

class Account {
    private rootKey: Uint8Array;
    private identityKeypair: eddsa.KeyPair;

    /**
     * Generate an account root key
     * @returns {ArrayBuffer}
     */
    generateRootKey() {
        const rootKey = window.crypto.getRandomValues(new Uint8Array(32));
        this.rootKey = rootKey;
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
        const signature = await this.signData(Buffer.from(ciphertext).toString("hex"));
        const encryptedKey: EncryptedKey = {
            key: Buffer.from(ciphertext).toString("hex"),
            signature: signature,
            iv: Buffer.from(iv).toString("hex"),
            salt: Buffer.from(salt).toString("hex")
        }

        return Promise.resolve(encryptedKey);
    }

    async decryptRootKey(password: string, account: EncryptedAccount): Promise<Uint8Array> {
        // First it would be beneficial to verify the signature
        // of the encrypted payload to check it hasn't been
        // tampered with server-side or in transport.
        const publicKey = ed25519.keyFromPublic(account.identity_publickey);
        const rootKeyHash = keccak256(account.encrypted_key.key);
        const validSignature = publicKey.verify(rootKeyHash, account.encrypted_key.signature);

        if (!validSignature) {
            return Promise.reject("Root key signature is invalid! Check that payload has not been tampered with.");
        }

        // Convert the Salt and IV back into byte form
        const saltBytes = new Uint8Array();
        new TextEncoder().encodeInto(account.encrypted_key.salt, saltBytes);

        const ivBytes = new Uint8Array();
        new TextEncoder().encodeInto(account.encrypted_key.iv, ivBytes);

        // Derive stretched Argon2 key from password
        const stretchedKey = await hash({
            pass: password,
            salt: saltBytes,
            type: ArgonType.Argon2id,
            hashLen: 32
        });

        // Derive the AES encryption key and decrypt the ciphertext to extract our Root Key
        const encryptionKey = await this.deriveAesEncryptionKey(stretchedKey.hash);

        try {
            const rootKey = await window.crypto.subtle.decrypt(
                { name: "AES-CBC", iv: ivBytes },
                encryptionKey,
                Buffer.from(account.encrypted_key.key)
            );

            return Promise.resolve(new Uint8Array(rootKey));
        } catch (e) {
            return Promise.reject("Password is incorrect, please try again!");
        }
    }

    /* Root Key Methods (Keypairs) */

    /**
     * Derives and sets the identity keypair for the account
     * @returns {void}
     */
    async deriveIdentityKeypair(): Promise<void> {
        // Check if root key is present in memory
        const rootKey = this.getRootKey();
        if (!rootKey) {
            return Promise.reject("Account root key is not set!");
        }

        // Key is constructed by SHA-256 hashing rootKey + keyType
        const keyType = new TextEncoder().encode(Keys.IDENTITY);
        const concatenatedKey = new Uint8Array([...rootKey!, ...keyType]);
        const secretKey = await window.crypto.subtle.digest("SHA-256", concatenatedKey);

        // Derive the identity EdDSA keypair from the secret and set it
        const keypair = ed25519.keyFromSecret(Buffer.from(secretKey));
        this.identityKeypair = keypair;
    }

    /**
     * Gets the account raw identity keypair
     * @returns {eddsa.KeyPair}
     */
    async getIdentityKeypair(): Promise<eddsa.KeyPair> {
        if (this.identityKeypair) {
            return Promise.resolve(this.identityKeypair)
        }

        await this.deriveIdentityKeypair();
        return Promise.resolve(this.identityKeypair);
    }

    /**
     * 
     * @param data - String data to be signed using Keccak256
     * @returns {string} - Hex-encoded signature
     */
    async signData(data: string): Promise<string> {
        // Convert the data into bytes and generate a Keccak256 hash of it
        const dataBytes = new TextEncoder().encode(data);
        const dataHash = keccak256(Buffer.from(dataBytes));

        // Generate the signature using keypair provided as parameter
        const identityKeypair = await this.getIdentityKeypair();
        const signature = identityKeypair.sign(dataHash).toHex().toLowerCase();
        
        return Promise.resolve(signature)
    }

    /**
     * Return a constructed object of a user account ready for API submission
     * @param username - Feirm account username
     * @param email - Feirm account email address
     * @param keypair - Root key identity keypair
     * @param encryptedKey - Encrypted root key
     * @returns 
     */
    async createEncryptedAccount(username: string, email: string, encryptedKey: EncryptedKey, token: EphemeralToken): Promise<EncryptedAccount> {
        const identityKeypair = await this.getIdentityKeypair();

        // Sign the provided ephemeral token
        const tokenSignature = await this.signData(token.nonce!);

        const encryptedAccount: EncryptedAccount = {
            email: email,
            username: username,
            identity_publickey: Buffer.from(identityKeypair.getPublic()).toString("hex"),
            encrypted_key: encryptedKey,
            token: {
                id: token.id,
                signature: tokenSignature
            }
        }

        return Promise.resolve(encryptedAccount);
    }
}

export { Account };