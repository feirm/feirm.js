interface EncryptedWallet {
  id: string;

  mnemonic: {
    ciphertext: string;
    iv: string;
    signature: string;
  };

  tokens: Token[];
}

interface Token {
  ticker: string;
  wallet_version: string;
  public: {
    xpub?: string;
    address?: string;
  }
}

export {
  EncryptedWallet,
  Token
}