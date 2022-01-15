interface EncryptedKey {
    key: string;
    signature: string;
    iv: string;
    salt: string;
}

export { EncryptedKey }