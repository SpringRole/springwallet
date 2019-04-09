import WalletInterface from "./WalletInterface";
class HDWalletInterface extends WalletInterface {
  constructor(pubkey, txSigner, msgSigner) {
    super(pubkey, true, identifier);
    this.txSigner = txSigner;
    this.msgSigner = msgSigner;
    this.errorHandler = errorHandler;
  }
  signTransaction(txParams) {
    return super.signTransaction(txParams, this.txSigner);
  }
  signMessage(msg) {
    return super.signMessage(msg, this.msgSigner);
  }
}
export default HDWalletInterface;
