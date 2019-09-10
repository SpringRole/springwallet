import {ethers} from 'ethers';
import {ATTESTATION_ABI, VANITYURL_ABI} from './abi';

export async function vanityReserve(txParams, wallet) {
    if (!wallet) {
        throw new Error('Please unlock your Springwallet');
    }

    const contract = new ethers.Contract(txParams.to, VANITYURL_ABI, wallet.provider);

    const contractWithSigner = contract.connect(wallet);
    const tx = await contractWithSigner.reserve(txParams.vanityUrl, txParams.springrole_id);
    return tx.hash;
}

export async function attest(txParams, wallet) {
    if (!wallet) {
        throw new Error('Please unlock your Springwallet');
    }

    const contract = new ethers.Contract(txParams.to, ATTESTATION_ABI, wallet.provider);
    const contractWithSigner = contract.connect(wallet);
    const tx = await contractWithSigner.write(txParams._type, txParams._data);
    return tx.hash;
}

export async function sendTransaction(txParams, wallet) {
    if (!wallet) {
        throw new Error('Please unlock your Springwallet');
    }

    const txCount = await wallet.provider.getTransactionCount(txParams.from);
    const transaction = {
        nonce: txCount,
        gasLimit: txParams.gasLimit,
        gasPrice: ethers.utils.bigNumberify(txParams.gasPrice),
        to: txParams.to,
        value: ethers.utils.parseEther(txParams.value),
        data: txParams.data,
        chainId: wallet.provider.network.chainId
    };

    const signedTransaction = await wallet.sign(transaction);
    const txResponse = await wallet.provider.sendTransaction(signedTransaction);
    return txResponse;
}
