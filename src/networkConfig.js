export default function networkConfig(network) {
    if (typeof network !== 'object') {
        throw new Error("illegal 'network' parameter");
    }

    if (!network.rpcUrl) {
        throw new Error("'rpcUrl' is not defined");
    }

    return network;
}
