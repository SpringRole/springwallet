import { generateMnemonic, validateMnemonic, mnemonicToSeed } from 'bip39';
import { randomBytes } from 'crypto';
import { hdkey } from 'ethereumjs-wallet';
import Web3ProviderEngine from 'web3-provider-engine';
import FixtureSubprovider from 'web3-provider-engine/subproviders/fixture.js';
import NonceSubprovider from 'web3-provider-engine/subproviders/nonce-tracker.js';
import RpcSubprovider from 'web3-provider-engine/subproviders/rpc.js';
import WebSocketSubProvider from 'web3-provider-engine/subproviders/websocket.js';
import HookedWalletSubprovider from 'web3-provider-engine/subproviders/hooked-wallet-ethtx.js';
import networkConfig from './networkConfig';
import { encryptMnemonic, decryptMnemonic } from './utils/encryption';

const STORAGE_SESSION_KEY = 'wallet-session';
const MNEMONIC_PATH = "m/44'/60'/0'/0/0";

/**
 * `SpringWallet` class
 */
export class SpringWallet {
    /**
     * @param {Object} network
     * @constructor
     */
    constructor(network) {
        if (!network) throw new Error("'network' not defined");
        this.network = networkConfig(network);
        this.wallet = undefined;
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
                web3_clientVersion: 'SpringWallet/v0.2.0/javascript',
                net_listening: true,
                eth_hashrate: '0x00',
                eth_mining: false,
                eth_syncing: true
            })
        );

        opts.getPrivateKey = (address, cb) => {
            if (address.toLowerCase() == this.walletAddress.toLowerCase()) {
                if (this.privateKey) {
                    cb(null, Buffer.from(this.privateKey, 'hex'));
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

        engine.addProvider(new NonceSubprovider());
        engine.addProvider(new HookedWalletSubprovider(opts));
        if (opts && opts.rpcUrl && opts.rpcUrl.indexOf && opts.rpcUrl.indexOf('wss://') == 0) {
            engine.addProvider(new WebSocketSubProvider(opts));
        } else {
            engine.addProvider(new RpcSubprovider(opts));
        }

        engine.start();
        return engine;
    }

    /**
     * Generate 12-words mnemonic phrase
     * @method generateMnemonic
     * @returns {String} mnemonic
     */
    static generateMnemonic() {
        return generateMnemonic(128, randomBytes);
    }

    /**
     * Check validity of 12-words mnemonic phrase
     * @method isValidMnemonic
     * @param {String} phrase
     * @returns {Boolean}
     */
    static isValidMnemonic(phrase) {
        return validateMnemonic(phrase);
    }

    /**
     * Encrypt Plain text mnemonic phrase
     * @method encryptMnemonic
     * @param {String} mnemonic phrase
     * @param {String} password
     * @returns {Promise<String>} encryptMnemonic
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
     * @returns {Object} encryptedMnemonic
     */
    static getWalletSession() {
        const data = localStorage.getItem(STORAGE_SESSION_KEY);
        if (!data) return null;
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
        const seed = await mnemonicToSeed(mnemonic);
        const hdKey = await hdkey.fromMasterSeed(seed);
        const wallet = await hdKey.derivePath(MNEMONIC_PATH).deriveChild(0).getWallet();
        return wallet;
    }

    static async unlockWallet(mnemonic) {
        const wallet = await SpringWallet.initializeWalletFromMnemonic(mnemonic);
        this.wallet = wallet;
        this.walletAddress = wallet.getChecksumAddressString();
        const privKey = wallet.getPrivateKey().toString('hex');
        this.privateKey = Buffer.from(privKey, 'hex');
        sessionStorage.setItem(STORAGE_SESSION_KEY, privKey);
        return this.walletAddress;
    }
}

export { encryptMnemonic, decryptMnemonic };
