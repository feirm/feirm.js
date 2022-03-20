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

  encrypted_private: {
    ciphertext: string;
    iv: string;
    signature: string;
  }
  
  public: {
    xpub?: string;
    address?: string;
  }
}

export {
  EncryptedWallet,
  Token
}