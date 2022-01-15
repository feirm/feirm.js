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

    async encryptRootKey(password: string): Promise<EncryptedKey> {
        // Check if root key is present in memory
        if (!this.rootKey) {
            Promise.reject("Account root key is not set!")
        }

        // Check if password paramater is valid
        if (password.trim().length === 0) {
            Promise.reject("Password parameter cannot be empty!");
        }

        // Generate salt used for password stretching and encryption IV of the root key
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(16));

        // Stretch password parameter into a stronger key
        const stretchedKey = await hash({
            pass: password,
            salt: salt,
            type: ArgonType.Argon2id,
            hashLen: 32
        });

        const encryptedKey: EncryptedKey = {
            key: stretchedKey.hash.toString(),
            signature: "0x",
            iv: iv.toString(),
            salt: salt.toString()
        }

        return Promise.resolve(encryptedKey);
    }
}

export { Account };