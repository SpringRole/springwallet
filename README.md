# SpringWallet

- [About](#about)
- [Documentation](#documentation)
- [Contributing](#contributing)

## About

SpringWallet - A simple wallet for flexible identity management

## Documentation

1.  Install `springwallet` with `npm`.

```bash
npm install springwallet --save
```

2. Import springwallet into your project.

```js
const SpringWallet = require('springwallet')
```

3. Generate 12 words random mnemonic

```js
const mnemonic = SpringWallet.generateMnemonic
```

4. Encrypt mnemonic with password

```js
SpringWallet.encryptMnemonic(mnemonic, password).then(function(encryptedMnemonic) {
    // DO Something
    console.log("Buffer of encryptedMnemonic:", encryptedMnemonic);
    console.log("Hex-encoded sttring of encryptedMnemonic:", encryptedMnemonic.toString('hex'));
})
```
5. Initalize a wallet

```js
SpringWallet.initializeWallet(encryptedMnemonic, password).then(function(walletAddress) {
    // DO Something
})
```
Initalize wallet is required when you are going to assign this particular wallet address to a specified user

6. Unlock a wallet

```js
SpringWallet.unlockWallet(encryptedMnemonic, password).then(function(keypair) {
    // DO Something like sign a transacrtion using web3
    web3.eth.accounts.signTransaction(tx, keypair.privateKey [, callback]);
})
```
This function returns wallet address and Buffer of a private key in JSON format

7. Store User's wallet details to browser's local storage

```js
SpringWallet.storeWalletDetails(id, address, encryptedMnemonic)
```
8. Fetch User's wallet details to browser's local storage

```js
SpringWallet.fetchWalletDetails(id).then(function(userWalletDetails){
    // Do something
})
```

## Contributing

TODO
