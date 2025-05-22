// Simple IPFS upload utility using web3.storage
// You must set WEB3_STORAGE_TOKEN in your environment for production use

// Upload file to backend proxy, which handles IPFS upload
export async function uploadToIPFS(file: File): Promise<string> {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch('/api/ipfs/upload', {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) throw new Error('Failed to upload to IPFS');
  const data = await res.json();
  // Return the first CID (for single file)
  return data.cids?.[0] || '';
}

// Helper to get IPFS gateway URL for a CID
export function ipfsUrl(cid: string): string {
  return `https://ipfs.io/ipfs/${cid}`;
}