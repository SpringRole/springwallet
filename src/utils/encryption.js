import {bip39} from 'bip39';
import {crypto} from 'crypto';

/**
 * Function to encrypt a mnemonic using password
 * @param phrase - string of the encrypted mnemonic
 * @return hex-encoded string of the encrypted mnemonic
 */
export async function encryptMnemonic(phrase, password) {
    if (!bip39.validateMnemonic(phrase)) {
        throw new Error('Not a valid bip39 mnemonic');
    }

    const plaintextBuffer = Buffer.from(bip39.mnemonicToEntropy(phrase), 'hex');

    // AES-128-CBC with SHA256 HMAC
    const salt = crypto.randomBytes(16);
    const keysAndIV = crypto.pbkdf2Sync(password, salt, 100000, 48, 'sha512');
    const encKey = keysAndIV.slice(0, 16);
    const macKey = keysAndIV.slice(16, 32);
    const iv = keysAndIV.slice(32, 48);

    const cipher = crypto.createCipheriv('aes-128-cbc', encKey, iv);

    const cipherText = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);

    const hmacPayload = Buffer.concat([salt, cipherText]);
    const hmac = crypto.createHmac('sha256', macKey);
    hmac.write(hmacPayload);
    const hmacDigest = hmac.digest();
    const payload = Buffer.concat([salt, hmacDigest, cipherText]);

    return payload.toString('hex');
}

/**
 * Decrypt a raw mnemonic phrase with a password
 * @param encryptedMnemonic - Hex-encoded string of the encrypted mnemonic
 * @param password - Password
 * @return plain text mnemonic phrase
 */
export async function decryptMnemonic(encryptedMnemonic, password) {
    const dataBuffer = Buffer.from(encryptedMnemonic, 'hex');

    const salt = dataBuffer.slice(0, 16);
    const hmacSig = dataBuffer.slice(16, 48);
    const cipherText = dataBuffer.slice(48);

    const hmacPayload = Buffer.concat([salt, cipherText]);
    const keysAndIV = crypto.pbkdf2Sync(password, salt, 100000, 48, 'sha512');
    const encKey = keysAndIV.slice(0, 16);
    const macKey = keysAndIV.slice(16, 32);
    const iv = keysAndIV.slice(32, 48);

    const decipher = crypto.createDecipheriv('aes-128-cbc', encKey, iv);
    const plaintextBuffer = Buffer.concat([decipher.update(cipherText), decipher.final()]);

    const hmac = crypto.createHmac('sha256', macKey);
    hmac.write(hmacPayload);

    const hmacDigest = hmac.digest();
    const hmacSigHash = crypto
        .createHash('sha256')
        .update(hmacSig)
        .digest()
        .toString('hex');

    const hmacDigestHash = crypto
        .createHash('sha256')
        .update(hmacDigest)
        .digest()
        .toString('hex');

    if (hmacSigHash !== hmacDigestHash) {
        throw new Error('Wrong password (HMAC mismatch)');
    }

    const mnemonic = bip39.entropyToMnemonic(plaintextBuffer);

    if (!bip39.validateMnemonic(mnemonic)) {
        throw new Error('Wrong password (invalid plaintext)');
    }

    return mnemonic;
}
