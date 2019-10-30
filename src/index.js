import * as bip39 from 'bip39';
import crypto from 'crypto';
import {ethers} from 'ethers';
import Swal from 'sweetalert2';
import Web3ProviderEngine from 'web3-provider-engine';
import FixtureSubprovider from 'web3-provider-engine/subproviders/fixture.js';
import RpcSubprovider from 'web3-provider-engine/subproviders/rpc.js';
import HookedWalletSubprovider from 'web3-provider-engine/subproviders/hooked-wallet-ethtx.js';
import {networkConfig} from './networkConfig';
import {encryptMnemonic, encryptSecret, decryptMnemonic, decryptSecret} from './utils/encryption';
import {vanityReserve, attest, sendTransaction} from './utils/transactions';

const STORAGE_SESSION_KEY = 'wallet-session';
const MNEMONIC_PATH = "m/44'/60'/0'/0/0";

/**
 * Fetch encrypted mnemonic from browser's local storage
 * @method getEncryptedMnemonic
 * @returns {String} encryptedMnemonic
 */
function getEncryptedMnemonic() {
    const data = localStorage.getItem(STORAGE_SESSION_KEY);
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
 * @param address - wallet address
 * @returns {Promise<String>} password
 */
async function getPassword() {
    const data = localStorage.getItem(STORAGE_SESSION_KEY);
    const address = JSON.parse(data).address;
    let encryptedPassword = sessionStorage.getItem(STORAGE_SESSION_KEY);

    if (!encryptedPassword) {
        const password = await promptPassword();

        if (password) {
            encryptedPassword = await encryptSecret(address, password);
            sessionStorage.setItem(STORAGE_SESSION_KEY, encryptedPassword);
            return password;
        }
    }
    return decryptSecret(address, encryptedPassword);
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
        this.provider = this.initProvider(network);
    }

    initProvider(opts) {
        const engine = new Web3ProviderEngine();
        engine.addProvider(
            new FixtureSubprovider({
                web3_clientVersion: 'SpringWallet/v0.1.7/javascript',
                net_listening: true,
                eth_hashrate: '0x00',
                eth_mining: false,
                eth_syncing: true
            })
        );

        opts.getPrivateKey = async (address, cb) => {
            if (address.toLowerCase() === this.walletAddress) {
                const privKey = this.wallet.getPrivateKey().toString('hex');
                cb(null, Buffer.from(privKey, 'hex'));
            } else {
                cb('unknown account');
            }
        };

        opts.getAccounts = async (cb) => {
            if (!this.wallet) {
                this.unlockWallet();
            }
            const address = await this.wallet.getChecksumAddressString();
            this.walletAddress = address;
            cb(false, [address]);
        };

        engine.addProvider(new HookedWalletSubprovider(opts));
        engine.addProvider(new RpcSubprovider(opts));
        engine.on('error', (error) => {
            console.error(error);
        });
        engine.start();
        return engine;
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
     * Check validity of 12-words mnemonic phrase
     * @method isValidMnemonic
     * @param {String} phrase
     * @returns {Boolean}
     */
    static isValidMnemonic(phrase) {
        return bip39.validateMnemonic(phrase);
    }

    /**
     * Returns wallet address
     * @method createWallet
     * @param {String} 12-words Plain mnemonic phrase
     * @returns {String} wallet address
     */
    static async createWallet(phrase, password) {
        if (!bip39.validateMnemonic(phrase)) {
            throw new Error('Not a valid bip39 mnemonic');
        }
        const wallet = ethers.Wallet.fromMnemonic(phrase, MNEMONIC_PATH);
        const address = await wallet.getAddress();
        const encryptedMnemonic = await encryptMnemonic(phrase, password);
        return {address, encryptedMnemonic};
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
     * Set wallet session in browser's localStorage
     * @method setWalletSession
     * @param {String} address - derived wallet address
     * @param {String} encryptedMnemonic
     */
    static setWalletSession(address, encryptedMnemonic) {
        localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify({address, encryptedMnemonic}));
    }

    /**
     * Initialize wallet from plain text mnemonic
     * @param mnemonic Plain text mnemonic phrase
     * @param path Mnemonic Path
     * @returns wallet instance
     */
    initializeWalletFromMnemonic(mnemonic) {
        const wallet = ethers.Wallet.fromMnemonic(mnemonic, MNEMONIC_PATH).connect(this.provider);
        return wallet;
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
        this.wallet = this.initializeWalletFromMnemonic(mnemonic);
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
    static async reinitializeWallet(address, encryptedMnemonic) {
        const password = await getPassword();
        const mnemonic = await decryptMnemonic(encryptedMnemonic, password);
        const Wallet = this.initializeWalletFromMnemonic(mnemonic, MNEMONIC_PATH);
        const derivedWalletAddress = await Wallet.getAddress();
        if (derivedWalletAddress !== address) {
            throw new Error('Not your wallet mnemonics');
        }
        SpringWallet.setWalletSession(address, encryptMnemonic);
        return true;
    }

    /**
     * Sign Message
     * @method signMessage
     * @param {<String>}
     * @returns {Promise<String>}
     */
    async signMessage(message) {
        return this.wallet.signMessage(message);
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

// export {decryptMnemonic};
