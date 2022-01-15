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

export { 
    Keys,
    EncryptedKey
}