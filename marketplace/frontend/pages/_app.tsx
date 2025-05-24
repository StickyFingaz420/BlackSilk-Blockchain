import '../styles/globals.css';
import type { AppProps } from 'next/app';
import { WalletProvider } from '../components/WalletProvider';
import Layout from '../components/Layout';

export default function App({ Component, pageProps }: AppProps) {
  return (
    <WalletProvider>
      <Layout>
        <Component {...pageProps} />
      </Layout>
    </WalletProvider>
  );
}