import { Html, Head, Main, NextScript } from 'next/document';

export default function Document() {
  return (
    <Html lang="en">
      <Head>
        {/* Security headers to prevent extension conflicts */}
        <meta httpEquiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https:; connect-src 'self' ws: wss: https:" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="description" content="BlackSilk Privacy-First Web Wallet" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      <body>
        <Main />
        <NextScript />
        {/* Prevent extension script conflicts */}
        <script
          dangerouslySetInnerHTML={{
            __html: `
              // Prevent extension errors from breaking the app
              window.addEventListener('error', function(e) {
                if (e.filename && e.filename.includes('chrome-extension://')) {
                  e.preventDefault();
                  return false;
                }
              });
              
              // Handle extension promise rejections
              window.addEventListener('unhandledrejection', function(e) {
                if (e.reason && e.reason.toString().includes('chrome-extension://')) {
                  e.preventDefault();
                  return false;
                }
              });
            `,
          }}
        />
      </body>
    </Html>
  );
}
