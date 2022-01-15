import { ArgonType, hash } from "argon2-browser"
import { EncryptedKey } from "./interfaces";

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
        const encryptionKey = await window.crypto.subtle.importKey(
            "raw",
            stretchedKey.hash,
            { name: "AES-CBC" },
            false,
            ["encrypt", "decrypt"]
        );

        // Encrypt the root key
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: "AES-CBC", iv: iv },
            encryptionKey,
            rootKey!
        )

        const encryptedKey: EncryptedKey = {
            key: Buffer.from(ciphertext).toString("hex"),
            signature: "0x",
            iv: Buffer.from(iv).toString("hex"),
            salt: Buffer.from(salt).toString("hex")
        }

        return Promise.resolve(encryptedKey);
    }
}

export { Account };