import { create } from 'ipfs-http-client';

const projectId = process.env.IPFS_PROJECT_ID || '';
const projectSecret = process.env.IPFS_PROJECT_SECRET || '';
const auth = 'Basic ' + Buffer.from(projectId + ':' + projectSecret).toString('base64');

const ipfs = create({
  host: 'ipfs.infura.io',
  port: 5001,
  protocol: 'https',
  headers: {
    authorization: auth,
  },
});

export const uploadToIPFS = async (file: File) => {
  try {
    const added = await ipfs.add(file);
    return added.path; // CID of the uploaded file
  } catch (error) {
    console.error('Error uploading to IPFS:', error);
    throw error;
  }
};
