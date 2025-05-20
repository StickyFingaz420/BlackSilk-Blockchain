export async function connectWallet(): Promise<string | null> {
  if (typeof window === 'undefined' || !(window as any).ethereum) {
    alert('MetaMask is not installed!');
    return null;
  }
  try {
    const accounts = await (window as any).ethereum.request({ method: 'eth_requestAccounts' });
    return accounts[0] as string;
  } catch (err) {
    alert('Wallet connection failed');
    return null;
  }
}

export async function getCurrentWallet(): Promise<string | null> {
  if (typeof window === 'undefined' || !(window as any).ethereum) {
    return null;
  }
  try {
    const accounts = await (window as any).ethereum.request({ method: 'eth_accounts' });
    return accounts[0] as string;
  } catch {
    return null;
  }
} 