import Web3 from 'web3';

const web3 = new Web3(process.env.NODE_API_URL || '');

export const sendTransaction = async (from: string, to: string, value: string, privateKey: string) => {
  try {
    const tx = {
      from,
      to,
      value: web3.utils.toWei(value, 'ether'),
      gas: 21000,
    };

    const signedTx = await web3.eth.accounts.signTransaction(tx, privateKey);
    if (!signedTx.rawTransaction) throw new Error('Failed to sign transaction');

    const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
    return receipt;
  } catch (error) {
    console.error('Error sending transaction:', error);
    throw error;
  }
};
