import { promisify } from 'util';
import { validateMnemonic, mnemonicToEntropy, entropyToMnemonic } from 'bip39';
import { pbkdf2, randomBytes, createCipheriv, createHmac, createDecipheriv, createHash } from 'crypto';

const asyncPbkdf2 = promisify(pbkdf2);

/**
 * Encrypt a mnemonic using password
 * @method encryptMnemonic
 * @param phrase - string of the encrypted mnemonic
 * @returns {Promise<String>} hex-encoded string of the encrypted mnemonic
 */
export async function encryptMnemonic(phrase, password) {
    if (!validateMnemonic(phrase)) {
        throw new Error('Not a valid bip39 mnemonic');
    }

    const plaintextBuffer = Buffer.from(mnemonicToEntropy(phrase), 'hex');

    // AES-128-CBC with SHA256 HMAC
    const salt = randomBytes(16);
    const keysAndIV = await asyncPbkdf2(password, salt, 100000, 48, 'sha512');
    const encKey = keysAndIV.slice(0, 16);
    const macKey = keysAndIV.slice(16, 32);
    const iv = keysAndIV.slice(32, 48);

    const cipher = createCipheriv('aes-128-cbc', encKey, iv);

    const cipherText = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);

    const hmacPayload = Buffer.concat([salt, cipherText]);
    const hmac = createHmac('sha256', macKey);
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
    const keysAndIV = await asyncPbkdf2(password, salt, 100000, 48, 'sha512');
    const encKey = keysAndIV.slice(0, 16);
    const macKey = keysAndIV.slice(16, 32);
    const iv = keysAndIV.slice(32, 48);

    const decipher = createDecipheriv('aes-128-cbc', encKey, iv);
    const plaintextBuffer = Buffer.concat([decipher.update(cipherText), decipher.final()]);

    const hmac = crypto.createHmac('sha256', macKey);
    hmac.write(hmacPayload);

    const hmacDigest = hmac.digest();
    const hmacSigHash = createHash('sha256').update(hmacSig).digest().toString('hex');

    const hmacDigestHash = createHash('sha256').update(hmacDigest).digest().toString('hex');

    if (hmacSigHash !== hmacDigestHash) {
        throw new Error('Wrong password (HMAC mismatch)');
    }

    const mnemonic = entropyToMnemonic(plaintextBuffer);

    if (!validateMnemonic(mnemonic)) {
        throw new Error('Wrong password (invalid plaintext)');
    }

    return mnemonic;
}
