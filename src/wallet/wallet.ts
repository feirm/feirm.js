import { entropyToMnemonic, validateMnemonic } from "bip39";

class Wallet {
    private mnemonic: string; // BIP39 mnemonic

    /**
     * Wallet constructor
     * @param mnemonic - BIP39 Mnemonic
     */
    constructor(mnemonic?: string) {
        if (mnemonic && this.validMnemonic(mnemonic)) {
            this.mnemonic = mnemonic;
        }
    }

    /**
     * Check if a mnemonic is BIP39 compliant
     * @param mnemonic 
     * @returns {boolean}
     */
    validMnemonic(mnemonic: string): boolean {
        const valid = validateMnemonic(mnemonic);
        return valid;
    }

    /**
     * Set BIP39 Mnemonic in memory
     * @param mnemonic - BIP39 Mnemonic
     * @returns {void}
     */
    setMnemonic(mnemonic: string): Promise<void> {
        if (!this.validMnemonic(mnemonic)) {
            return Promise.reject("Mnemonic is invalid!");
        }

        this.mnemonic = mnemonic;
        return Promise.resolve();
    }

    /**
     * Securely generate a 24 word BIP39 mnemonic
     * @returns {string}
     */
    generateMnemonic(): string {
        // Generate some secure entropy and use it to create a 24 word mnemonic
        const entropy = window.crypto.getRandomValues(new Uint8Array(32));
        const mnemonic = entropyToMnemonic(Buffer.from(entropy));
        
        return mnemonic;
    }
}

export {
    Wallet
}