const bip39 = require('bip39');
const crypto = require('crypto');
const ethers = require('ethers');

const MNEMONIC_PATH = "m/44'/60'/0'/0/0";
const SPRINGROLE_RPC_URL = 'https://chain.springrole.com';
const SprinChain_ID = 202242799;

let walletInstance;

const ATTESTATION_ABI = [
  'event Attest(address _address,string _type,string _data)',
  'function write(string _type,string _data) public returns (bool)'
];

const VANITYURL_ABI = [
  'event VanityReserved(address _to, string _vanity_url)',
  'function reserve(string _vanity_url,string _springrole_id)',
  'function changeVanityURL(string _vanity_url, string _springrole_id)'
];

var SpringWallet = function() {};

SpringWallet.storeHexPassword = async function storeHexPassword(
  password
) {
  let hexPassword = Buffer.from(password, 'utf-8').toString('hex');
  sessionStorage.setItem('pwd', hexPassword);
};

SpringWallet.getPassword = function getPassword() {
  let password = Buffer.from(sessionStorage.getItem('pwd'), 'hex').toString();
  if(!password) {
    //TODO: create promptPassword function  
    return promptPassword();
  }

  return password;
}

/**
 * Function to generate 12 words random mnemonic phrase
 */
SpringWallet.generateMnemonic = bip39.generateMnemonic(128, crypto.randomBytes);

/**
 * Function to initlalize Wallet on user device using encrypted mnemonic and password
 * @param encryptedMnemonic - hex-encoded string of the encrypted mnemonic
 * @return walet address
 */
SpringWallet.initializeAndUnlockWallet = async function initializeAndUnlockWallet(
  encryptedMnemonic
) {

  const password = await getPassword();
  const mnemonic = await decryptMnemonic(encryptedMnemonic, password);
  const Wallet = ethers.Wallet.fromMnemonic(mnemonic, MNEMONIC_PATH);
  const address = Wallet.getAddress();
  localStorage.setItem(address, encryptedMnemonic);
  await unlockWallet(address);
  return address;
};

/**
 * Function to encrypt a mnemonic using password
 * @param phrase - string of the encrypted mnemonic
 * @return hex-encoded string of the encrypted mnemonic
 */
SpringWallet.encryptMnemonic = function encryptMnemonic(phrase) {
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
    const keysAndIV = crypto.pbkdf2Sync(
      await getPassword(),
      salt,
      100000,
      48,
      'sha512'
    );
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

/**
 * Function to fetch user wallet's encrypted mnemonic from browser's session storage
 * @param address - user wallet address
 */
function getEncryptedMnemonic(address) {
  if (!localStorage.getItem(address)) {
    // get encrypted keys from server
    return Error('User not logged in');
  }
  return localStorage.getItem(address);
}

SpringWallet.fetchWalletBalance = function fetchWalletBalance(address) {
  let httpProvider = new ethers.providers.JsonRpcProvider(SPRINGROLE_RPC_URL);
  return httpProvider.getBalance(address).then(balance => {
    // balance is a BigNumber (in wei); format is as a sting (in ether)
    return ethers.utils.formatEther(balance);
  });
};

/**
 * Function to unlock a wallet using provided encryptedMnemonic and password
 * @param address - Wallet address
 * @param password - plain text password
 */
async function unlockWallet(address) {
  const password = await getPassword();
  const encryptedMnemonic = getEncryptedMnemonic(address);
  const mnemonic = await decryptMnemonic(encryptedMnemonic, password);
  walletInstance = ethers.Wallet.fromMnemonic(mnemonic, MNEMONIC_PATH);
  return true;
}
SpringWallet.unlockWallet = unlockWallet;

SpringWallet.sendVanityReserveTransaction = async function sendVanityReserveTransaction(
  txParams
) {
  if (!walletInstance) {
    await unlockWallet();
  }
  let httpProvider = new ethers.providers.JsonRpcProvider(SPRINGROLE_RPC_URL);
  let contract = new ethers.Contract(txParams.to, VANITYURL_ABI, httpProvider);
  let contractWithSigner = contract.connect(walletInstance);
  let tx = await contractWithSigner.reserve(
    txParams.vanityUrl,
    txParams.springrole_id
  );
  return tx.hash;
};

SpringWallet.sendAttestationTransaction = async function sendAttestationTransaction(
  txParams
) {
  if (!walletInstance) {
    await unlockWallet();
  }

  let httpProvider = new ethers.providers.JsonRpcProvider(SPRINGROLE_RPC_URL);
  let contract = new ethers.Contract(
    txParams.to,
    ATTESTATION_ABI,
    httpProvider
  );
  let contractWithSigner = contract.connect(walletInstance);
  let tx = await contractWithSigner.write(txParams._type, txParams._data);
  return tx.hash;
};

SpringWallet.sendTransaction = async function sendTransaction(txParams) {
  if (!walletInstance) {
    await unlockWallet();
  }

  let httpProvider = new ethers.providers.JsonRpcProvider(SPRINGROLE_RPC_URL);
  let transaction = {
    nonce: await httpProvider.getTransactionCount(tx.from),
    gasLimit: txParams.gasLimit,
    gasPrice: ethers.utils.bigNumberify(txParams.gasPrice),
    to: txParams.to,
    value: ethers.utils.parseEther(txParams.value),
    data: txParams.data,
    chainId: SprinChain_ID
  };

  return walletInstance.sign(transaction).then(signedTransaction => {
    return httpProvider.sendTransaction(signedTransaction);
  });
};

module.exports = SpringWallet;
