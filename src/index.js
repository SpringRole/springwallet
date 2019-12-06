import * as bip39 from 'bip39';
import crypto from 'crypto';
import * as HDKey from 'ethereumjs-wallet/hdkey';
import Web3ProviderEngine from 'web3-provider-engine';
import FixtureSubprovider from 'web3-provider-engine/subproviders/fixture.js';
import RpcSubprovider from 'web3-provider-engine/subproviders/rpc.js';
import HookedWalletSubprovider from 'web3-provider-engine/subproviders/hooked-wallet-ethtx.js';
import networkConfig from './networkConfig';
import { encryptMnemonic, decryptMnemonic } from './utils/encryption';

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
        this.walletAddress = this.initWalletAddress();
        this.privateKey = this.initPrivateKey();
        this.provider = this.initProvider(this.network);
    }

    initWalletAddress() {
        let walletSession = SpringWallet.getWalletSession();
        if (!walletSession) {
            return null;
        }
        return walletSession.address;
    }

    initPrivateKey() {
        let privateKey = sessionStorage.getItem(STORAGE_SESSION_KEY);
        if (!privateKey) {
            return null;
        }
        return privateKey;
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

        opts.getPrivateKey = (address, cb) => {
            if (address.toLowerCase() === this.walletAddress.toLowerCase()) {
                if (this.privateKey) {
                    cb(null, this.privateKey);
                } else if (this.wallet) {
                    const privKey = this.wallet.getPrivateKey().toString('hex');
                    cb(null, Buffer.from(privKey, 'hex'));
                } else {
                    cb('unlock wallet');
                }
            } else {
                cb('unknown account');
            }
        };

        opts.getAccounts = (cb) => {
            let address;
            if (this.walletAddress) {
                address = this.walletAddress;
            } else if (this.wallet) {
                address = this.wallet.getChecksumAddressString();
                this.walletAddress = address;
            }

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
            return null;
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
    static async initializeWalletFromMnemonic(mnemonic) {
        const hdKey = await HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic));
        const wallet = await hdKey
            .derivePath(MNEMONIC_PATH)
            .deriveChild(0)
            .getWallet();
        return wallet;
    }

    async unlockWallet(mnemonic) {
        const wallet = await SpringWallet.initializeWalletFromMnemonic(mnemonic);
        this.wallet = wallet;
        this.walletAddress = wallet.getChecksumAddressString();
        const privKey = wallet.getPrivateKey().toString('hex');
        this.privateKey = Buffer.from(privKey, 'hex');
        sessionStorage.setItem(STORAGE_SESSION_KEY, privKey);
        return this.walletAddress;
    }
}
