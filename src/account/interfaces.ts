// Key types
enum Keys {
    ENCRYPTION = "enc",
    IDENTITY = "identity",
}

interface EncryptedKey {
    key: string;
    signature: string;
    iv: string;
    salt: string;
}

interface EncryptedAccount {
    email?: string;
    username: string;
    identity_publickey: string;
    encrypted_key: EncryptedKey;
    created_at?: number;
    version?: number;
    totp?: TOTP;

    token?: EphemeralToken;
}

// Representation of an ephemeral token signature payload
interface EphemeralToken {
    id?: string;
    nonce?: string;
    signature?: string;
}

// Representation of a signed session token
interface SignedSessionToken {
    token_id: string;
    signature: string;
}

// Representation for TOTP field on sign-up
interface TOTP {
    secret?: string;
    token?: string;
}


export {
    Keys,
    EncryptedKey,
    EncryptedAccount,
    EphemeralToken,
    SignedSessionToken
}