import { mnemonicToSeedSync, generateMnemonic } from "bip39";

import * as Wallet from "ethereumjs-wallet";

import HDKey from "ethereumjs-wallet/hdkey";

const MNEMONIC_PATH = "m/44'/60'/0'/0/0";

export { generateMnemonic };

export function generateRandomWallet(srID, randomMnemonic, password) {
  const hdKey = HDKey.fromMasterSeed(
    mnemonicToSeedSync(randomMnemonic, password)
  );
  const wallet = hdKey
    .derivePath(MNEMONIC_PATH)
    .deriveChild(0)
    .getWallet();
  const address = wallet.getChecksumAddressString();
  const v3Json = wallet.toV3String(password);
  storeWallet(srID, address, v3Json);
  const res = [];
  res.push(address);
  res.push(v3Json);
  return res;
}

export function setCurrentUser(srID) {
  localStorage.setItem("currentUser", srID);
  console.log("welcome, " + srID);
}

export function getCurrentUser() {
  return localStorage.getItem("currentUser");
}

function storeWallet(srID, address, jsonWallet) {
  const usrData = {
    srid: srID,
    address: address,
    v3JSON: jsonWallet
  };

  localStorage.setItem(srID, JSON.stringify(usrData));
  setCurrentUser(srID);
}

function fetchWallet(srID) {
  const usrData = JSON.parse(localStorage.getItem(srID));
  return usrData.v3JSON;
}

export function unlockWallet(password) {
  const currUser = getCurrentUser();
  const v3Json = fetchWallet(currUser);
  const unlockedWallet = Wallet.fromV3(v3Json, password);
  const privateKey = new Buffer(
    unlockedWallet.getPrivateKey().toString("hex"),
    "hex"
  );
  return privateKey;
}
