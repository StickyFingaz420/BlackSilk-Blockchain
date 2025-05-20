// Simple IPFS upload utility using web3.storage
// You must set WEB3_STORAGE_TOKEN in your environment for production use

export async function uploadToIPFS(file: File): Promise<string> {
  const apiToken = process.env.NEXT_PUBLIC_WEB3_STORAGE_TOKEN;
  if (!apiToken) throw new Error('Missing IPFS API token');

  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch('https://api.web3.storage/upload', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiToken}`,
    },
    body: formData,
  });

  if (!res.ok) throw new Error('Failed to upload to IPFS');
  const data = await res.json();
  // Return the IPFS hash (CID)
  return data.cid;
} 