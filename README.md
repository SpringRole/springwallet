# SpringWallet

- [About](#about)
- [Documentation](#documentation)
- [Contributing](#contributing)

## About

SpringWallet - A simple wallet for flexible identity management

## Usage

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

4. Store Hex Password in Client and return hashed password for login purpose.

```js
SpringWallet.storeAndHashPassword(password).then(function(hashedPassword) {
    // Do login with hashed password
    console.log("Hashed password:", hashedPassword);
})
```
5. Encrypt mnemonic

```js
SpringWallet.encryptMnemonic(mnemonic).then(function(encryptedMnemonic) {
    // DO Something
    console.log("encryptedMnemonic:", encryptedMnemonic));
})
```
Note: mnemonic will be encrypted with the stored password in client side.

6. Initalize a wallet

```js
SpringWallet.initializeWallet(encryptedMnemonic).then(function(walletAddress) {
    // DO Something
})
```
Initalize wallet is required when you are going to assign this particular wallet address to a specified user

7. Unlock a wallet

```js
SpringWallet.initializeAndUnlockWallet(encryptedMnemonic).then(function(address) {
    // Do Something like map user id to it's wallet address in database
    console.log("address:", address);
})
```
8. Fetch User's wallet details to browser's local storage

```js
SpringWallet.fetchWalletDetails(id).then(function(userWalletDetails){
    // Do something
})
```

## Contributing

TODO
