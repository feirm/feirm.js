import bip39 from "bip39";

abstract class Wallet {
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
        const valid = bip39.validateMnemonic(mnemonic);
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
        const mnemonic = bip39.entropyToMnemonic(Buffer.from(entropy));
        
        return mnemonic;
    }

    /**
     * Add an additional passphrase to BIP39 mnemonic
     * @param passphrase - An additional word (passphrase) to act as the 25th word
     */
    addPassphrase(passphrase: string): Promise<void> {
        // Check for mnemonic and validate it first
        if (this.mnemonic && !this.validMnemonic(this.mnemonic)) {
            return Promise.reject("Mnemonic is invalid!");
        }

        // Override the existing mnemonic to bypass validation of BIP39 library
        const mnemonic = `${this.mnemonic} ${passphrase}`;
        this.mnemonic = mnemonic;

        return Promise.resolve();
    }
}