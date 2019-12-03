const networks = {
    mainnet: {
        rpcUrl: 'https://mainnet.infura.io/v3/607d0ccc6e364affa61439c855e1188a',
        chainId: '1'
    },
    maticAlpha: {
        rpcUrl: 'https://alpha.ethereum.matic.network',
        chainId: '4626'
    },
    maticBeta: {
        rpcUrl: 'https://beta.matic.network',
        chainId: '15001'
    }
};

export default function networkConfig(network) {
    // TODO: Add infura mainnet prod url
    const nObj = typeof network === 'string' ? Object.assign({}, networks[network]) : network;

    if (typeof nObj !== 'object') {
        throw new Error("illegal 'network' parameter");
    }

    if (!nObj.rpcUrl) {
        throw new Error("'rpcUrl' is not defined");
    }

    return nObj;
}
