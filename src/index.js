import * as HDKey from "hdkey";
import bip39 from "bip39";
import ethTx from "ethereumjs-tx";
import { hashPersonalMessage, toBuffer, ecsign } from "ethereumjs-util";
import HDWalletInterface from "./HDWalletInterface";
import { getSignTransactionObject, calculateChainIdFromV } from "./utils";


const MNEMONIC_PATH = "m/44'/60'/0'/0/0";

class MnemonicWallet {
  constructor(mnemonic, password) {
    if (!bip39.validateMnemonic(mnemonic)) throw new Error("Invalid Mnemonic");
    this.mnemonic = mnemonic;
    this.password = password;
  }
  async init() {
    this.hdKey = HDKey.fromMasterSeed(
      bip39.mnemonicToSeedSync(this.mnemonic, this.password)
    );
  }
  getAccount() {
    const derivedKey = this.hdKey.derive(MNEMONIC_PATH);
    const txSigner = async tx => {
      tx = new ethTx(tx);
      const networkId = tx._chainId;
      tx.sign(derivedKey.privateKey);
      const signedChainId = calculateChainIdFromV(tx.v);
      if (signedChainId !== networkId)
        throw new Error(
          "Invalid networkId signature returned. Expected: " +
            networkId +
            ", Got: " +
            signedChainId,
          "InvalidNetworkId"
        );
      return getSignTransactionObject(tx);
    };
    const msgSigner = async msg => {
      const msgHash = hashPersonalMessage(toBuffer(msg));
      const signed = ecsign(msgHash, derivedKey.privateKey);
      return Buffer.concat([
        Buffer.from(signed.r),
        Buffer.from(signed.s),
        Buffer.from([signed.v])
      ]);
    };
    return new HDWalletInterface(
      derivedKey.publicKey,
      txSigner,
      msgSigner
    );
  }
}
const createWallet = async (mnemonic, password) => {
  const _mnemonicWallet = new MnemonicWallet(mnemonic, password);
  await _mnemonicWallet.init();
  return _mnemonicWallet;
};

export default createWallet;
