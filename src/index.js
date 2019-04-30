const bip39 = require('bip39');
const crypto = require('crypto');
const HDKey = require('ethereumjs-wallet/hdkey');
const MNEMONIC_PATH = "m/44'/60'/0'/0/0";

var SpringWallet = function() {};

/**
 * Function to generate 12 words random mnemonic phrase
 */
SpringWallet.generateMnemonic = bip39.generateMnemonic(128, crypto.randomBytes);

/**
 * Function to create Wallet using encrypted mnemonic and password
 * @param data - Buffer or hex-encoded string of the encrypted mnemonic
 * @param password - Password for data
 * @return the wallet address
 */
SpringWallet.initializeWallet = async function initializeWallet(
  encryptedMnemonic,
  password
) {
  const mnemonic = await decryptMnemonic(encryptedMnemonic, password);
  const hdKey = HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic));
  const wallet = hdKey
    .derivePath(MNEMONIC_PATH)
    .deriveChild(0)
    .getWallet();
  const address = wallet.getChecksumAddressString();
  return address;
};

SpringWallet.encryptMnemonic = function encryptMnemonic(phrase, password) {
  return Promise.resolve().then(() => {
    if (!bip39.validateMnemonic(phrase)) {
      throw new Error('Not a valid bip39 nmemonic');
    }

    const plaintextNormalized = Buffer.from(
      bip39.mnemonicToEntropy(phrase),
      'hex'
    );

    // AES-128-CBC with SHA256 HMAC
    const salt = crypto.randomBytes(16);
    const keysAndIV = crypto.pbkdf2Sync(password, salt, 100000, 48, 'sha512');
    const encKey = keysAndIV.slice(0, 16);
    const macKey = keysAndIV.slice(16, 32);
    const iv = keysAndIV.slice(32, 48);

    const cipher = crypto.createCipheriv('aes-128-cbc', encKey, iv);
    let cipherText = cipher.update(plaintextNormalized).toString('hex');
    cipherText += cipher.final().toString('hex');

    const hmacPayload = Buffer.concat([salt, Buffer.from(cipherText, 'hex')]);

    const hmac = crypto.createHmac('sha256', macKey);
    hmac.write(hmacPayload);
    const hmacDigest = hmac.digest();

    const payload = Buffer.concat([
      salt,
      hmacDigest,
      Buffer.from(cipherText, 'hex')
    ]);
    return payload;
  });
};

function decryptMnemonicBuffer(dataBuffer, password) {
  return Promise.resolve().then(() => {
    const salt = dataBuffer.slice(0, 16);
    const hmacSig = dataBuffer.slice(16, 48);
    const cipherText = dataBuffer.slice(48);
    const hmacPayload = Buffer.concat([salt, cipherText]);

    const keysAndIV = crypto.pbkdf2Sync(password, salt, 100000, 48, 'sha512');
    const encKey = keysAndIV.slice(0, 16);
    const macKey = keysAndIV.slice(16, 32);
    const iv = keysAndIV.slice(32, 48);

    const decipher = crypto.createDecipheriv('aes-128-cbc', encKey, iv);

    let plaintext = decipher.update(cipherText).toString('hex');
    plaintext += decipher.final().toString('hex');

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

    const mnemonic = bip39.entropyToMnemonic(plaintext);

    if (!bip39.validateMnemonic(mnemonic)) {
      throw new Error('Wrong password (invalid plaintext)');
    }
    return mnemonic;
  });
}

/**
 * Decrypt a raw mnemonic phrase with a password
 * @param data - Buffer or hex-encoded string of the encrypted mnemonic
 * @param password - Password for data
 * @return the raw mnemonic phrase
 */
async function decryptMnemonic(data, password) {
  const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'hex');
  return decryptMnemonicBuffer(dataBuffer, password);
}
SpringWallet.decryptMnemonic = decryptMnemonic;

/**
 * Function to set currently loggedin user in a local storage
 */
SpringWallet.setCurrentUser = function setCurrentUser(id) {
  localStorage.setItem('currentUser', id);
};

/**
 * Function to get currently loggedin user from a local storage
 */
SpringWallet.getCurrentUser = function getCurrentUser() {
  return localStorage.getItem('currentUser');
};

/**
 * Function to get user wallet address using ID from local storage
 */
SpringWallet.getUserAddress = function getUserAddress(id) {
  const usrData = JSON.parse(localStorage.getItem(id));
  return usrData.address;
};

/**
 * Function to store user encrypted JSON wallet and address in local storage
 */
SpringWallet.storeEncryptedMnemonic = function storeEncryptedMnemonic(
  id,
  address,
  encryptMnemonic
) {
  const usrData = {
    id: id,
    address: address,
    emnemonic: encryptMnemonic
  };

  localStorage.setItem(id, JSON.stringify(usrData));
  setCurrentUser(id);
};

/**
 * Function to fetch encrypted mnemonic from local storage
 */
SpringWallet.fetchEncryptedMnemonic = function fetchEncryptedMnemonic(id) {
  const usrData = JSON.parse(localStorage.getItem(id));
  return usrData.emnemonic;
};

/**
 * Function to unlock encrypted JSON wallet from local storage
 * @returns privatekey
 */
SpringWallet.unlockWallet = async function unlockWallet(encryptedMnemonic, password) {
  const mnemonic = await decryptMnemonic(encryptedMnemonic, password);
  const hdKey = HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic));
  const wallet = hdKey
    .derivePath(MNEMONIC_PATH)
    .deriveChild(0)
    .getWallet();
  const address = wallet.getChecksumAddressString();
  const privateKey = Buffer.from(wallet.getPrivateKey().toString('hex'), 'hex');
  const keypair = {
    address: address,
    privateKey: privateKey
  };
  return keypair;
};

module.exports = SpringWallet;
