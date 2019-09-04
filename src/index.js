/* eslint-disable arrow-parens */
/* eslint-disable comma-dangle */
const bip39 = require('bip39');
const crypto = require('crypto');
const ethers = require('ethers');
const swal = require('sweetalert2');

const MNEMONIC_PATH = "m/44'/60'/0'/0/0";
const SPRINGROLE_RPC_URL = 'https://chain.springrole.com';
const SPRINGCHAIN_ID = 202242799;
const STORAGE_SESSION_KEY = 'wallet-session';

const ATTESTATION_ABI = [
  'event Attest(address _address,string _type,string _data)',
  'function write(string _type,string _data) public returns (bool)'
];

const VANITYURL_ABI = [
  'event VanityReserved(address _to, string _vanity_url)',
  'function reserve(string _vanity_url,string _springrole_id)',
  'function changeVanityURL(string _vanity_url, string _springrole_id)'
];

const httpProvider = new ethers.providers.JsonRpcProvider(SPRINGROLE_RPC_URL);

let walletInstance;

// eslint-disable-next-line func-names
const SpringWallet = function () {};

/**
 * Function to encrypt password
 */
async function encryptContent(plaintext) {
  const key = crypto
    .createHash('md5')
    .update(plaintext)
    .digest('hex');
  const paddedKey = Buffer.from('0'.repeat(32).concat(key), 'hex');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', paddedKey, iv);
  const encryptedData = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);
  const ciphertext = Buffer.concat([paddedKey, iv, encryptedData]).toString(
    'hex'
  );
  return ciphertext;
}

/**
 * Function to decrypt password
 */
async function decryptContent(ciphertext) {
  const dataBuffer = Buffer.from(ciphertext, 'hex');
  const key = dataBuffer.slice(0, 32);
  const iv = dataBuffer.slice(32, 48);
  const encryptedData = dataBuffer.slice(48);
  const cipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const decryptedData = Buffer.concat([
    cipher.update(encryptedData),
    cipher.final()
  ]);
  return decryptedData.toString();
}

/**
 * Function to prompt for password
 */
async function promptPassword() {
  const { value: password } = await swal.fire({
    title: 'Enter your password',
    input: 'password',
    inputPlaceholder: 'Enter your password',
    inputAttributes: {
      maxlength: 50,
      autocapitalize: 'off',
      autocorrect: 'off'
    }
  });

  if (!password) {
    throw new Error('Password not entered');
  }

  return password;
}

/**
 * Function to store user encrypted password.
 */
SpringWallet.storePassword = async password => {
  const encryptedPassword = await encryptContent(password);
  sessionStorage.setItem(STORAGE_SESSION_KEY, encryptedPassword);
};

/**
 * Function to get decrypted Password.
 */
async function getPassword() {
  let password = sessionStorage.getItem(STORAGE_SESSION_KEY);

  if (!password) {
    password = await promptPassword();

    if (password) {
      await SpringWallet.storePassword(password);
      return password;
    }

    return password.catch(err => err);
  }
  const decryptPassword = await decryptContent(password);
  return decryptPassword;
}

/**
 * Function to generate 12 words random mnemonic phrase
 */
SpringWallet.generateMnemonic = () => bip39.generateMnemonic(128, crypto.randomBytes);

/**
 * Function to encrypt a mnemonic using password
 * @param phrase - string of the encrypted mnemonic
 * @return hex-encoded string of the encrypted mnemonic
 */
SpringWallet.encryptMnemonic = async phrase => {
  if (!bip39.validateMnemonic(phrase)) {
    throw new Error('Not a valid bip39 mnemonic');
  }

  const password = await getPassword();
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

  return payload.toString('hex');
};

async function decryptMnemonicBuffer(dataBuffer, password) {
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
}

/**
 * Decrypt a raw mnemonic phrase with a password
 * @param encryptedMnemonic - Buffer or hex-encoded string of the encrypted mnemonic
 * @param password - Password
 * @return raw mnemonic phrase
 */
async function decryptMnemonic(encryptedMnemonic, password) {
  const dataBuffer = Buffer.isBuffer(encryptedMnemonic)
    ? encryptedMnemonic
    : Buffer.from(encryptedMnemonic, 'hex');
  const mnemonic = await decryptMnemonicBuffer(dataBuffer, password);
  return mnemonic;
}
// SpringWallet.decryptMnemonic = decryptMnemonic;

/**
 * Function to fetch user wallet's encrypted mnemonic from browser's local storage
 */
function getEncryptedMnemonic() {
  const data = localStorage.getItem(STORAGE_SESSION_KEY);
  if (!data) {
    return Error('User not logged in');
  }
  const { encryptedMnemonic } = JSON.parse(data);
  return encryptedMnemonic;
}

/**
 * Function to fetch user wallet balance
 */
SpringWallet.fetchWalletBalance = async () => {
  const data = localStorage.getItem(STORAGE_SESSION_KEY);
  const { address } = JSON.parse(data);
  const balance = await httpProvider.getBalance(address);
  return ethers.utils.formatEther(balance);
};

/**
 * Function to unlock a wallet using provided encryptedMnemonic and password
 */
async function unlockWallet() {
  const password = await getPassword();
  const encryptedMnemonic = await getEncryptedMnemonic();
  const mnemonic = await decryptMnemonic(encryptedMnemonic, password);
  walletInstance = ethers.Wallet.fromMnemonic(mnemonic, MNEMONIC_PATH).connect(
    httpProvider
  );
  return true;
}

/**
 * Function to initialize Wallet on user device using encrypted mnemonic and password
 * Also stores address and encryptedMnemonic in localStorage
 * @param encryptedMnemonic - hex-encoded string of the encrypted mnemonic
 * @return wallet address
 */
SpringWallet.initializeAndUnlockWallet = async encryptedMnemonic => {
  const password = await getPassword();
  const mnemonic = await decryptMnemonic(encryptedMnemonic, password);
  const Wallet = ethers.Wallet.fromMnemonic(mnemonic, MNEMONIC_PATH).connect(
    httpProvider
  );
  const address = await Wallet.getAddress();
  const store = { address, encryptedMnemonic };
  localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify(store));
  await unlockWallet();
  return address;
};

SpringWallet.sendVanityReserveTransaction = async txParams => {
  if (!walletInstance) {
    await unlockWallet();
  }

  const contract = new ethers.Contract(txParams.to, VANITYURL_ABI, httpProvider);
  const contractWithSigner = contract.connect(walletInstance);
  const tx = await contractWithSigner.reserve(
    txParams.vanityUrl,
    txParams.springrole_id
  );
  return tx.hash;
};

SpringWallet.sendAttestationTransaction = async txParams => {
  if (!walletInstance) {
    await unlockWallet();
  }

  const contract = new ethers.Contract(
    txParams.to,
    ATTESTATION_ABI,
    httpProvider
  );
  const contractWithSigner = contract.connect(walletInstance);
  // eslint-disable-next-line no-underscore-dangle
  const tx = await contractWithSigner.write(txParams._type, txParams._data);
  return tx.hash;
};

SpringWallet.sendTransaction = async txParams => {
  if (!walletInstance) {
    await unlockWallet();
  }

  const txCount = await httpProvider.getTransactionCount(txParams.from);
  const transaction = {
    nonce: txCount,
    gasLimit: txParams.gasLimit,
    gasPrice: ethers.utils.bigNumberify(txParams.gasPrice),
    to: txParams.to,
    value: ethers.utils.parseEther(txParams.value),
    data: txParams.data,
    chainId: SPRINGCHAIN_ID
  };

  const signedTransaction = await walletInstance.sign(transaction);
  const txResponse = await httpProvider.sendTransaction(signedTransaction);
  return txResponse;
};

window.SpringWallet = SpringWallet;

module.exports = SpringWallet;
