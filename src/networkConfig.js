const networks = {
    mainnet: {
        rpcUrl: 'https://mainnet.infura.io/v3/faa4639b090f46499f29d894da0551a0',
        chainId: '1'
    },
    maticAlpha: {
        rpcUrl: 'https://alpha.ethereum.matic.network',
        chainId: '4626'
    },
    maticTestnet: {
        rpcUrl: 'https://testnet2.matic.network',
        chainId: '8995'
    }
};

export function networkConfig(network) {
    let nObj;
    if (typeof network === 'string') {
        nObj = networks[network];
    }

    if (typeof nObj !== 'object') {
        throw new Error("illegal 'network' parameter");
    }

    if (!nObj.rpcUrl) {
        throw new Error("'rpcUrl' is not defined");
    }

    return nObj;
}
