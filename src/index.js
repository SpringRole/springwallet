const bip39 = require('bip39');
const HDKey = require('ethereumjs-wallet/hdkey');
const MNEMONIC_PATH = "m/44'/60'/0'/0/0";

var SpringWallet = function() {};

/**
 * Function to generate random mnemonic phrase
 */
SpringWallet.generateMnemonic = bip39.generateMnemonic;

/**
 * Function to create Wallet using provided mnemonic and password
 */
SpringWallet.generateRandomWallet = function generateRandomWallet(
  id,
  randomMnemonic,
  password
) {
  const hdKey = HDKey.fromMasterSeed(
    bip39.mnemonicToSeedSync(randomMnemonic, password)
  );
  const wallet = hdKey
    .derivePath(MNEMONIC_PATH)
    .deriveChild(0)
    .getWallet();
  const address = wallet.getChecksumAddressString();
  const v3Json = wallet.toV3String(password);
  storeWallet(id, address, v3Json);
  const res = [];
  res.push(address);
  res.push(v3Json);
  return res;
};

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
function storeWallet(id, address, jsonWallet) {
  const usrData = {
    id: id,
    address: address,
    v3JSON: jsonWallet
  };

  localStorage.setItem(id, JSON.stringify(usrData));
  setCurrentUser(id);
}

SpringWallet.storeWallet = storeWallet;

/**
 * Function to fetch encrypted JSON wallet from local storage
 */
SpringWallet.fetchWallet = function fetchWallet(id) {
  const usrData = JSON.parse(localStorage.getItem(id));
  return usrData.v3JSON;
};

/**
 * Function to unlock encrypted JSON wallet from local storage
 * @returns privatekey
 */
SpringWallet.unlockWallet = function unlockWallet(password) {
  const currUser = getCurrentUser();
  const v3Json = fetchWallet(currUser);
  const unlockedWallet = Wallet.fromV3(v3Json, password);
  const privateKey = new Buffer(
    unlockedWallet.getPrivateKey().toString('hex'),
    'hex'
  );
  return privateKey;
};

module.exports = SpringWallet;
