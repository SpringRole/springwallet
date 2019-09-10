import * as bip39 from 'bip39';
import {ethers} from 'ethers';
import Swal from 'sweetalert2';
import {networkConfig} from './networkConfig';
import {encryptMnemonic, encryptSecret, decryptMnemonic, decryptSecret} from './utils/encryption';
import {vanityReserve, attest, sendTransaction} from './utils/transactions';

/**
 * Fetch encrypted mnemonic from browser's local storage
 * @method getEncryptedMnemonic
 * @returns {String} encryptedMnemonic
 */
function getEncryptedMnemonic() {
    const data = localStorage.getItem(this.storage_session_key);
    if (!data) {
        return Error('User not logged in');
    }
    const {encryptedMnemonic} = JSON.parse(data);
    return encryptedMnemonic;
}

/**
 * Prompt for wallet password
 * @method promptPassword
 * @returns {Promise<String>} password
 */
async function promptPassword() {
    const {value: password} = await Swal.fire({
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
 * Get wallet password from encrypted password
 * @method getPassword
 * @param email - wallet user email
 * @returns {Promise<String>} password
 */
async function getPassword(email) {
    let encryptedPassword = sessionStorage.getItem(this.storage_session_key);

    if (!encryptedPassword) {
        const password = await promptPassword();

        if (password) {
            encryptedPassword = await encryptSecret(email, password);
            sessionStorage.setItem(this.storage_session_key, encryptedPassword);
            return password;
        }
    }
    return decryptSecret(email, encryptedPassword);
}

/**
 * `SpringWallet` class
 */
export default class SpringWallet {
    /**
     * @param {Object|String} network
     * @constructor
     */
    constructor(network) {
        if (!network) {
            throw new Error("'network' not defined");
        }
        this.network = network;
        this.storage_session_key = 'wallet-session';
        this.mnemonic_path = "m/44'/60'/0'/0/0";
        this.provider = this.setProvider(networkConfig(network));
    }

    /**
     * Set Provider
     * @param {Object|String} network
     * @returns {HttpProvider} httpProvider
     */
    setProvider(network) {
        const httpProvider = new ethers.providers.JsonRpcProvider(network.rpcUrl);
        return httpProvider;
    }

    /**
     * Set Provider
     * @method changeNetwork
     * @param {Object|String} network
     * @returns {HttpProvider} httpProvider
     */
    changeNetwork(newNetwork) {
        this.network = newNetwork;
        this.provider = this.setProvider(networkConfig(newNetwork));
    }

    /**
     * Generate 12-words mnemonic phrase
     * @method generateMnemonic
     * @returns {String} mnemonic
     */
    static generateMnemonic() {
        return bip39.generateMnemonic(128, crypto.randomBytes);
    }

    /**
     * Encrypt Plain text mnemonic phrase
     * @method encryptMnemonic
     * @param {Object|String} network
     * @returns {Promise<HttpProvider>} httpProvider
     */
    static encryptMnemonic(phrase, password) {
        return encryptMnemonic(phrase, password);
    }

    /**
     * Initialize wallet from plain text mnemonic
     * @param mnemonic Plain text mnemonic phrase
     * @param path Mnemonic Path
     * @returns wallet instance
     */
    initializeWalletFromMnemonic(mnemonic, path) {
        const wallet = ethers.Wallet.fromMnemonic(mnemonic, path).connect(this.provider);
        return wallet;
    }

    /**
     * Set wallet session in browser's localStorage
     * @method setWalletSession
     * @param {String} address - derived wallet address
     * @param {String} encryptedMnemonic
     */
    setWalletSession(address, encryptedMnemonic) {
        localStorage.setItem(this.storage_session_key, JSON.stringify({address, encryptedMnemonic}));
    }

    /**
     * Unlocks a wallet
     * @method unlockWallet
     * @param {String} encryptedMnemonic
     * @returns {Promise<Boolean>}
     */
    async unlockWallet() {
        const password = await getPassword();
        const encryptedMnemonic = getEncryptedMnemonic();
        const mnemonic = await decryptMnemonic(encryptedMnemonic, password);
        this.wallet = this.initializeWalletFromMnemonic(mnemonic, this.mnemonic_path);
        return true;
    }

    /**
     * Reinitializes a wallet with new encrypted mnemonic
     * checks if the derived wallet address is same
     * @method reinitializeWallet
     * @param {String} address - wallet address
     * @param {String} encryptedMnemonic - new encrypted mnemonic
     * @returns {Promise<Boolean>}
     */
    async reinitializeWallet(address, encryptedMnemonic) {
        const password = await getPassword();
        const mnemonic = await decryptMnemonic(encryptedMnemonic, password);
        const Wallet = this.initializeWalletFromMnemonic(mnemonic, this.mnemonic_path);
        const derivedWalletAddress = await Wallet.getAddress();
        if (derivedWalletAddress !== address) {
            throw new Error('Not your wallet mnemonics');
        }
        this.setWalletSession(address, encryptMnemonic);
        return true;
    }

    /**
     * Get wallet Ether Balance
     * @method fetchWalletEthBalance
     * @returns {Promise<String|Number>}
     */
    async fetchWalletEthBalance() {
        const address = await this.wallet.getAddress();
        const balance = await this.provider.getBalance(address);
        return ethers.utils.formatEther(balance);
    }

    /**
     * Send Vanity Reserve transaction to blockchain
     * @method sendVanityReserveTransaction
     * @param txParams
     * @returns {Promise<String>} txHash
     */
    async sendVanityReserveTransaction(txParams) {
        if (!this.wallet) {
            await this.unlockWallet();
        }
        return vanityReserve(txParams, this.wallet);
    }

    /**
     * Send an Attestation transaction to blockchain
     * @method sendAttestationTransaction
     * @param txParams
     * @returns {Promise<String>} txHash
     */
    async sendAttestationTransaction(txParams) {
        if (!this.wallet) {
            await this.unlockWallet();
        }
        return attest(txParams, this.wallet);
    }

    /**
     * Send generic transaction to blockchain
     * @method sendTransaction
     * @param txParams
     * @returns {Promise<String>} txHash
     */
    async sendTransaction(txParams) {
        if (!this.wallet) {
            await this.unlockWallet();
        }
        return sendTransaction(txParams, this.wallet);
    }
}
