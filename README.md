# SpringWallet

-   [About](#about)
-   [Usage](#usage)
-   [Contributing](#contributing)

## About

SpringWallet - A simple wallet for flexible identity management for your frontend application

#### Basic Usage

1.  Install `springwallet` with `npm`.

    ```npm install springwallet --save``` or ```yarn add springwallet```

2. Import springwallet into your project.

    ```js 
    import SpringWallet from '@springrole/springwallet';
    ```
3. Generate 12 words random mnemonic

    ```js
    const mnemonic = SpringWallet.generateMnemonic();
    ```
4. Create a new wallet using plain text mnemonic and encrypt it with password

    ```js
    async function createWallet(plainTextMnemonic, password) {
        const encryptedMnemonic = await encryptMnemonic(plainTextMnemonic, password); // encrypting mnemonic
        const wallet = await SpringWallet.initializeWalletFromMnemonic(plainTextMnemonic); // initializing wallet 
        const address = wallet.getChecksumAddressString(); // wallet address
        const key = wallet.getPrivateKey().toString('hex'); // private key
        await SpringWallet.setWalletSession(address, encryptedMnemonic); // saving wallet session in localStorage
        sessionStorage.setItem('wallet-session', key); // persist wallet private key in sessionStorage
        return true;
    }
    ```

   **Note**:  encrypted mnemonic and address of the wallet will be store in localStorage at key 'wallet-session'

5. Fetch wallet's address and encrypted mnemonic

    ```js
    const { address, encryptedMnemonic } = SpringWallet.getWalletSession();
    ```
6. Decrypt encryptedMnemonic and unlock wallet

    ```js
    async function unlockWallet(encryptedMnemonic, password) {
      let plainTextMnemonic;
      try {
        plainTextMnemonic = await decryptMnemonic(encryptedMnemonic, password);
      } catch {
        return false;
      }
      return SpringWallet.unlockWallet(plainTextMnemonic);
    }
    ```

7. Use SpringWallet provider with web3.js

    ```js
    const springwallet = new SpringWallet({
        rpcUrl: "http://localhost:8545",
        chainId: "1337"
      });
    
    const web3 = new Web3(springwallet.provider);
    return web3;
    ```
    **NOTE** SpringWallet needs to be unlocked before performing any web3 actions, like `getAccounts()`, `getBalance()`

#### Advance Usage

1. Change SpringWallet password

    ```js
    async function changeWalletPassword(address, encryptedMnemonic, oldPassword, newPassword) {
      const mnemonicPhrase = await decryptMnemonic(encryptedMnemonic, oldPassword);
      const newEncryptedMnemonic = await encryptMnemonic(mnemonicPhrase, newPassword);
      const status = await updateEncryptedMnemonic(address, newEncryptedMnemonic);
      return status;
    }
    ```
    **NOTE** This will decrypt mnemonic with old password and reencrypts it using new password which will create new encrypted mnemonic 
    
2. Reset SpringWallet password, needs the plaintext mnemonic 

    ```js
    async function resetWalletPassword(plainTextMnemonic, newPassword) {
      const newEncryptedMnemonic = await encryptMnemonic(plainTextMnemonic, newPassword);
      const wallet = await SpringWallet.initializeWalletFromMnemonic(plainTextMnemonic);
      const walletAddress = wallet.getChecksumAddressString();
      const status = await updateEncryptedMnemonic(walletAddress, newEncryptedMnemonic);
      return status;
    }
    ```
    
## Contributing

TODO
