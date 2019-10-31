import * as bip39 from 'bip39';
import crypto from 'crypto';
import * as HDKey from 'ethereumjs-wallet/hdkey';
import Swal from 'sweetalert2';
import Web3ProviderEngine from 'web3-provider-engine';
import FixtureSubprovider from 'web3-provider-engine/subproviders/fixture.js';
import RpcSubprovider from 'web3-provider-engine/subproviders/rpc.js';
import HookedWalletSubprovider from 'web3-provider-engine/subproviders/hooked-wallet-ethtx.js';
import networkConfig from './networkConfig';
import {encryptMnemonic, encryptSecret, decryptMnemonic, decryptSecret} from './utils/encryption';

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
        return {address, encryptedMnemonic};
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
        const hdKey = HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic));
        const wallet = hdKey
            .derivePath(MNEMONIC_PATH)
            .deriveChild(0)
            .getWallet();
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
        const derivedWalletAddress = await Wallet.getChecksumAddressString();
        if (derivedWalletAddress !== address) {
            throw new Error('Different wallet mnemonics');
        }
        SpringWallet.setWalletSession(address, encryptMnemonic);
        return true;
    }
}

export {decryptMnemonic};
