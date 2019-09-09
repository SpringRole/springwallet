import {bip39} from 'bip39';
import {ethers} from 'ethers';
import swal from 'sweetalert2';
import {networkConfig} from './networkConfig';
import {ATTESTATION_ABI, VANITYURL_ABI} from './utils/abi';

export default class SpringWallet {
    constructor(network) {
        if (!network) {
            throw new Error("'network' not defined");
        }
        this.network = network;
        this.storage_session_key = 'wallet-session';
        this.mnemonic_path = "m/44'/60'/0'/0/0";
        this.provider = this.setProvider(networkConfig(network));
    }

    setProvider(network) {
        const httpProvider = new ethers.providers.JsonRpcProvider(network.rpcUrl);
        return httpProvider;
    }

    changeNetwork(newNetwork) {
        this.network = newNetwork;
        this.provider = this.setProvider(networkConfig(newNetwork));
    }

    generateMnemonic() {
        return bip39.generateMnemonic(128, crypto.randomBytes);
    }

    /**
     * Function to fetch user wallet's encrypted mnemonic from browser's local storage
     */
    getEncryptedMnemonic() {
        const data = localStorage.getItem(this.storage_session_key);
        if (!data) {
            return Error('User not logged in');
        }
        const {encryptedMnemonic} = JSON.parse(data);
        return encryptedMnemonic;
    }

    /**
     * Function to encrypt password
     */
    async encryptSecret(email, password) {
        const salt = crypto.randomBytes(16);
        const keysAndIV = crypto.pbkdf2Sync(email, salt, 100000, 32, 'sha512');

        const encKey = keysAndIV.slice(0, 16);
        const iv = keysAndIV.slice(16);

        const cipher = crypto.createCipheriv('aes-128-cbc', encKey, iv);
        const encryptedData = Buffer.concat([cipher.update(password), cipher.final()]);
        const secret = Buffer.concat([salt, encryptedData]).toString('hex');
        return secret;
    }

    /**
     * Function to decrypt password
     */
    async decryptSecret(email, secret) {
        const dataBuffer = Buffer.from(secret, 'hex');
        const salt = dataBuffer.slice(0, 16);
        const encryptedSecret = dataBuffer.slice(16);

        const keysAndIV = crypto.pbkdf2Sync(email, salt, 100000, 32, 'sha512');
        const encKey = keysAndIV.slice(0, 16);
        const iv = keysAndIV.slice(16);

        const cipher = crypto.createDecipheriv('aes-128-cbc', encKey, iv);
        const decryptedSecret = Buffer.concat([cipher.update(encryptedSecret), cipher.final()]);
        return decryptedSecret.toString();
    }

    /**
     * Function to prompt for password
     */
    async promptPassword() {
        const {value: password} = await swal.fire({
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

    async getPassword(email) {
        let encryptedPassword = sessionStorage.getItem(this.storage_session_key);

        if (!encryptedPassword) {
            const password = await this.promptPassword();

            if (password) {
                encryptedPassword = await this.encryptSecret(email, password);
                sessionStorage.setItem(this.storage_session_key, encryptedPassword);
                return password;
            }
        }
        return this.decryptSecret(email, encryptedPassword);
    }

    initializeWalletFromMnemonic(mnemonic, path) {
        this.wallet = ethers.Wallet.fromMnemonic(mnemonic, path).connect(this.provider);
        return this.wallet;
    }

    async getWalletAddress() {
        return this.wallet.getAddress();
    }

    /**
     * Function to unlock a wallet using provided encryptedMnemonic and password
     */
    async unlockWallet() {
        const password = await this.getPassword();
        const encryptedMnemonic = this.getEncryptedMnemonic();
        const mnemonic = await this.decryptMnemonic(encryptedMnemonic, password);
        this.initializeWalletFromMnemonic(mnemonic, this.mnemonic_path);
        return true;
    }

    static async initializeAndUnlockWallet(email, encryptedMnemonic) {
        const password = await this.getPassword();
        const mnemonic = await this.decryptMnemonic(encryptedMnemonic, password);
        const Wallet = this.initializeWalletFromMnemonic(mnemonic, this.mnemonic_path);
        const address = await Wallet.getAddress();
        const store = {email, address, encryptedMnemonic};
        localStorage.setItem(this.storage_session_key, JSON.stringify(store));
        await this.unlockWallet();
        return address;
    }

    async fetchWalletEthBalance() {
        const data = localStorage.getItem(this.storage_session_key);
        const {address} = JSON.parse(data);
        const balance = this.provider.getBalance(address);
        return ethers.utils.formatEther(balance);
    }

    async sendVanityReserveTransaction(txParams) {
        if (!this.wallet) {
            await this.unlockWallet();
        }

        const contract = new ethers.Contract(txParams.to, VANITYURL_ABI, this.provider);

        const contractWithSigner = contract.connect(this.wallet);
        const tx = await contractWithSigner.reserve(txParams.vanityUrl, txParams.springrole_id);
        return tx.hash;
    }

    async sendAttestationTransaction(txParams) {
        if (!this.wallet) {
            await this.unlockWallet();
        }

        const contract = new ethers.Contract(txParams.to, ATTESTATION_ABI, this.provider);
        const contractWithSigner = contract.connect(this.wallet);
        const tx = await contractWithSigner.write(txParams._type, txParams._data);
        return tx.hash;
    }

    async sendTransaction(txParams) {
        if (!this.wallet) {
            await this.unlockWallet();
        }

        const txCount = await this.httpProvider.getTransactionCount(txParams.from);
        const transaction = {
            nonce: txCount,
            gasLimit: txParams.gasLimit,
            gasPrice: ethers.utils.bigNumberify(txParams.gasPrice),
            to: txParams.to,
            value: ethers.utils.parseEther(txParams.value),
            data: txParams.data,
            chainId: this.network.chainId
        };

        const signedTransaction = await this.wallet.sign(transaction);
        const txResponse = await this.provider.sendTransaction(signedTransaction);
        return txResponse;
    }
}

// window.SpringWallet = SpringWallet;
