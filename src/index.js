import * as bip39 from 'bip39';
import crypto from 'crypto';
import * as HDKey from 'ethereumjs-wallet/hdkey';
import Web3ProviderEngine from 'web3-provider-engine';
import FixtureSubprovider from 'web3-provider-engine/subproviders/fixture.js';
import RpcSubprovider from 'web3-provider-engine/subproviders/rpc.js';
import HookedWalletSubprovider from 'web3-provider-engine/subproviders/hooked-wallet-ethtx.js';
import networkConfig from './networkConfig';
import { encryptMnemonic, encryptSecret, decryptMnemonic, decryptSecret } from './utils/encryption';

const STORAGE_SESSION_KEY = 'wallet-session';
const MNEMONIC_PATH = "m/44'/60'/0'/0/0";

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
        this.network = networkConfig(network);
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
            if (address.toLowerCase() === this.walletAddress.toLowerCase()) {
                const privKey = this.wallet.getPrivateKey().toString('hex');
                cb(null, Buffer.from(privKey, 'hex'));
            } else {
                cb('unknown account');
            }
        };

        opts.getAccounts = async (cb) => {
            const address = this.wallet.getChecksumAddressString();
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
        const encryptedMnemonic = await encryptMnemonic(phrase, password);
        const hdKey = HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(phrase));
        const wallet = hdKey
            .derivePath(MNEMONIC_PATH)
            .deriveChild(0)
            .getWallet();
        const address = wallet.getChecksumAddressString();
        return { address, encryptedMnemonic };
    }

    /**
     * Encrypt Plain text mnemonic phrase
     * @method encryptMnemonic
     * @param {String} mnemonic phrase
     * @param {String} password
     * @returns {String} encryptMnemonic
     */
    static encryptMnemonic(phrase, password) {
        return encryptMnemonic(phrase, password);
    }

    /**
     * Decrypt an encrypted mnemonic with a password
     * @method decryptMnemonic
     * @param {String} encryptedMnemonic - Hex-encoded string of the encrypted mnemonic
     * @param {String} password - Password
     * @return {Promise<String>} mnemonic - plain text mnemonic phrase
     */
    static decryptMnemonic(encryptedMnemonic, password) {
        return decryptMnemonic(encryptedMnemonic, password);
    }

    /**
     * Function to encrypt password
     * @method encryptSecret
     * @param {String} address - user wallet address
     * @param {String} password - password to encrypt
     * @returns {Promise<String>} hex encoded encrypted password
     */
    static encryptSecret(address, password) {
        return encryptSecret(address, password);
    }

    /**
     * Function to decrypt password
     * @method decryptSecret
     * @param {String} address - user address
     * @param {String} secret - encrypted password
     * @returns {Promise<String>} decrypted password
     */
    static decryptSecret(address, secret) {
        return decryptSecret(address, secret);
    }

    /**
     * Set wallet session in browser's localStorage
     * @method setWalletSession
     * @param {String} address - derived wallet address
     * @param {String} encryptedMnemonic
     */
    static setWalletSession(address, encryptedMnemonic) {
        localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify({ address, encryptedMnemonic }));
    }

    /**
     * Fetch encrypted mnemonic from browser's local storage
     * @method getEncryptedMnemonic
     * @returns {String} encryptedMnemonic
     */
    static getWalletSession() {
        const data = localStorage.getItem(STORAGE_SESSION_KEY);
        if (!data) {
            return Error('User not logged in');
        }

        const { address, encryptedMnemonic } = JSON.parse(data);
        return { address, encryptedMnemonic };
    }

    /**
     * Initialize wallet from plain text mnemonic
     * @param mnemonic Plain text mnemonic phrase
     * @param path Mnemonic Path
     * @returns wallet instance
     */
    async initializeWalletFromMnemonic(mnemonic) {
        const hdKey = await HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic));
        const wallet = await hdKey
            .derivePath(MNEMONIC_PATH)
            .deriveChild(0)
            .getWallet();
        return wallet;
    }
}
