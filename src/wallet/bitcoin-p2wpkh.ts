import { Wallet } from "../wallet/wallet";

class BitcoinP2WPKH extends Wallet {
    private xpub: string;
    private zpub: string;

    constructor() {
        super();
        
    }
}

export { BitcoinP2WPKH };