import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Filter out extension-related errors
    const message = error.message || '';
    const stack = error.stack || '';
    
    if (message.includes('chrome-extension://') || 
        stack.includes('chrome-extension://') ||
        message.includes('inpage.js') ||
        stack.includes('inpage.js')) {
      // Reset error state for extension errors
      this.setState({ hasError: false, error: null });
      return;
    }

    console.error('Error caught by boundary:', error, errorInfo);
  }

  render() {
    if (this.state.hasError && this.state.error) {
      // Filter out extension errors in render
      const message = this.state.error.message || '';
      const stack = this.state.error.stack || '';
      
      if (message.includes('chrome-extension://') || 
          stack.includes('chrome-extension://') ||
          message.includes('inpage.js') ||
          stack.includes('inpage.js')) {
        return this.props.children;
      }

      return (
        <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-xl p-8 max-w-md w-full">
            <div className="text-center">
              <div className="text-red-500 text-6xl mb-4">⚠️</div>
              <h1 className="text-2xl font-bold text-gray-900 mb-4">Something went wrong</h1>
              <p className="text-gray-600 mb-6">
                The application encountered an unexpected error. Please try refreshing the page.
              </p>
              <button
                onClick={() => window.location.reload()}
                className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
              >
                Refresh Page
              </button>
              <details className="mt-4 text-left">
                <summary className="cursor-pointer text-gray-500 text-sm">Technical Details</summary>
                <pre className="mt-2 p-2 bg-gray-100 rounded text-xs overflow-auto">
                  {this.state.error.message}
                </pre>
              </details>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
