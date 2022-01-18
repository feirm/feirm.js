import { Wallet } from "../wallet/wallet";

class BitcoinP2WPKH extends Wallet {
    private xpub: string;
    private zpub: string;
}

export { BitcoinP2WPKH };