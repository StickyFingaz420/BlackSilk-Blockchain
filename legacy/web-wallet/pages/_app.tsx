import type { AppProps } from 'next/app';
import { useEffect } from 'react';
import '../src/styles/globals.css';

export default function App({ Component, pageProps }: AppProps) {
  useEffect(() => {
    // Prevent browser extension conflicts
    if (typeof window !== 'undefined') {
      // Override console errors from extensions
      const originalError = console.error;
      console.error = function(...args) {
        // Filter out extension-related errors
        const message = args[0]?.toString() || '';
        if (message.includes('chrome-extension://') || 
            message.includes('extension') ||
            message.includes('inpage.js')) {
          return; // Ignore extension errors
        }
        originalError.apply(console, args);
      };

      // Handle unhandled promise rejections from extensions
      window.addEventListener('unhandledrejection', (event) => {
        const message = event.reason?.toString() || '';
        if (message.includes('chrome-extension://') || 
            message.includes('extension') ||
            message.includes('inpage.js')) {
          event.preventDefault();
          return;
        }
      });

      // Prevent extension script injection conflicts
      const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              const element = node as Element;
              if (element.tagName === 'SCRIPT' && 
                  element.getAttribute('src')?.includes('chrome-extension://')) {
                // Let extension scripts load but prevent conflicts
                element.setAttribute('data-extension', 'true');
              }
            }
          });
        });
      });

      observer.observe(document.head, { childList: true, subtree: true });

      return () => {
        observer.disconnect();
      };
    }
  }, []);

  return <Component {...pageProps} />;
}
