import * as bip39 from 'bip39';
import * as crypto from 'crypto';

/**
 * Encrypt a mnemonic using password
 * @method encryptMnemonic
 * @param phrase - string of the encrypted mnemonic
 * @returns {Promise<String>} hex-encoded string of the encrypted mnemonic
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
 * Decrypt an encrypted mnemonic with a password
 * @method decryptMnemonic
 * @param {String} encryptedMnemonic - Hex-encoded string of the encrypted mnemonic
 * @param {String} password - Password
 * @return {Promise<String>} mnemonic - plain text mnemonic phrase
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

/**
 * Function to encrypt password
 * @method encryptSecret
 * @param {String} address - user wallet address
 * @param {String} password - password to encrypt
 * @returns {Promise<String>} hex encoded encrypted password
 */
export async function encryptSecret(address, password) {
    const salt = crypto.randomBytes(16);
    const keysAndIV = crypto.pbkdf2Sync(address, salt, 100000, 32, 'sha512');

    const encKey = keysAndIV.slice(0, 16);
    const iv = keysAndIV.slice(16);

    const cipher = crypto.createCipheriv('aes-128-cbc', encKey, iv);
    const encryptedData = Buffer.concat([cipher.update(password), cipher.final()]);
    const secret = Buffer.concat([salt, encryptedData]).toString('hex');
    return secret;
}

/**
 * Function to decrypt password
 * @method decryptSecret
 * @param {String} address - user address
 * @param {String} secret - encrypted password
 * @returns {Promise<String>} decrypted password
 */
export async function decryptSecret(address, secret) {
    const dataBuffer = Buffer.from(secret, 'hex');
    const salt = dataBuffer.slice(0, 16);
    const encryptedSecret = dataBuffer.slice(16);

    const keysAndIV = crypto.pbkdf2Sync(address, salt, 100000, 32, 'sha512');
    const encKey = keysAndIV.slice(0, 16);
    const iv = keysAndIV.slice(16);

    const cipher = crypto.createDecipheriv('aes-128-cbc', encKey, iv);
    const decryptedSecret = Buffer.concat([cipher.update(encryptedSecret), cipher.final()]);
    return decryptedSecret.toString();
}
