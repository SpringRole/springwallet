# SpringWallet

- [About](#about)
- [Usage](#usage)
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
const mnemonic = SpringWallet.generateMnemonic();
```

4. Store encrypted Password in Client

```js
SpringWallet.storePassword(password);
```
Note: Plain text password will be the input and the encrypted password will be stored in browser's sessionStorage at key 'wallet-session'

5. Encrypt mnemonic

```js
SpringWallet.encryptMnemonic(mnemonic).then(function(encryptedMnemonic) {
    // Do Something like initialize wallet
    console.log("encryptedMnemonic:", encryptedMnemonic));
    SpringWallet.initializeAndUnlockWallet(encryptedMnemonic);
})
```
Note: mnemonic will be encrypted with the stored password in client side.

6. Initalize a wallet and unlocks it simultaneously

```js
SpringWallet.initializeAndUnlockWallet(encryptedMnemonic).then(function(walletAddress) {
    // Do Something
})
```
Note: This function will initalize a wallet instance also this will store wallet address and encryptedMnemonic in localStorage at key 'wallet-session'  

7. Fetch User's balance

```js
SpringWallet.fetchWalletBalance().then(function(balance) {
    // Do something
    console.log("user balance:", balance);
})
```
8. Generic sendTransaction function to interact with SpringChain 

```js
txParams = {
    from: "user address",
    to: "receiver address OR contract address",
    gasLimit: "gas limit",
    gasPrice: "gas price", 
    value: "value to send",
    data: "abi encoded data"
};

SpringWallet.sendTransaction(txParams).then(function(txHash) {
    // Do Something 
    console.log("transaction hash:", txHash);
})
```

9. Call reserve function of Vanity contract of Springrole platform 

```js
txParams = {
    from: "user address",
    to: "VanityURL contract address",
    vanityUrl: "vanity url",
    springrole_id: "User springrole id"  
};

SpringWallet.sendVanityReserveTransaction(txParams).then(function(txHash) {
    // Do Something 
    console.log("transaction hash:", txHash);
})
```
10. Call write function of Attestation contract of Springrole platform 

```js
txParams = {
    from: "user address",
    to: "Attestation contract address",
    _type_: "type of attestation",
    _data: "Data"  
}

SpringWallet.sendAttestationTransaction(txParams).then(function(txHash) {
    // Do Something
    console.log("transaction hash:", txHash);
})
```

## Contributing

TODO
