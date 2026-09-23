import React from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { NextPageContext, NextPage } from 'next';
import { NodeStatus, PrivacyIndicator } from '../components';
import { PrivacyLevel } from '../types';

interface ErrorProps {
  statusCode?: number;
  hasGetInitialPropsRun?: boolean;
  err?: Error & { statusCode?: number };
}

const CustomError: NextPage<ErrorProps> = ({ statusCode, hasGetInitialPropsRun, err }) => {
  const getErrorMessage = () => {
    switch (statusCode) {
      case 400:
        return {
          title: 'Bad Request',
          description: 'The request could not be understood by the server due to malformed syntax.',
          emoji: '❌'
        };
      case 401:
        return {
          title: 'Unauthorized',
          description: 'You need to be logged in to access this resource.',
          emoji: '🔐'
        };
      case 403:
        return {
          title: 'Forbidden',
          description: 'You don\'t have permission to access this resource.',
          emoji: '🚫'
        };
      case 404:
        return {
          title: 'Not Found',
          description: 'The page you\'re looking for could not be found.',
          emoji: '🔍'
        };
      case 500:
        return {
          title: 'Internal Server Error',
          description: 'An unexpected error occurred on our servers. Our team has been notified.',
          emoji: '⚡'
        };
      case 502:
        return {
          title: 'Bad Gateway',
          description: 'The server received an invalid response from the upstream server.',
          emoji: '🌐'
        };
      case 503:
        return {
          title: 'Service Unavailable',
          description: 'The service is temporarily unavailable. Please try again later.',
          emoji: '🔧'
        };
      default:
        return {
          title: 'Something Went Wrong',
          description: 'An unexpected error occurred. Please try again later.',
          emoji: '💀'
        };
    }
  };

  const errorInfo = getErrorMessage();

  return (
    <>
      <Head>
        <title>{`Error ${statusCode || 'Unknown'} - BlackSilk Marketplace`}</title>
        <meta name="description" content={`Error ${statusCode || 'Unknown'}: ${errorInfo.description}`} />
      </Head>

      <div className="min-h-screen bg-gray-900 text-white">
        <div className="container mx-auto px-4 py-8">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center space-x-4">
              <Link href="/" className="text-purple-400 hover:text-purple-300">
                ← Back to Marketplace
              </Link>
              <PrivacyIndicator level={PrivacyLevel.High} />
            </div>
            <NodeStatus />
          </div>

          {/* Error Content */}
          <div className="flex flex-col items-center justify-center text-center py-20">
            {/* Large Error Code */}
            <div className="mb-8">
              <div className="text-6xl mb-4">{errorInfo.emoji}</div>
              <h1 className="text-6xl font-bold text-red-500 mb-4">{statusCode || 'ERROR'}</h1>
              <div className="w-32 h-1 bg-gradient-to-r from-red-500 to-pink-500 mx-auto"></div>
            </div>

            {/* Error Message */}
            <div className="max-w-md mb-8">
              <h2 className="text-2xl font-semibold mb-4">{errorInfo.title}</h2>
              <p className="text-gray-400 mb-6">{errorInfo.description}</p>
            </div>

            {/* Error Details for Development */}
            {process.env.NODE_ENV === 'development' && err && (
              <div className="bg-gray-800 rounded-lg p-6 max-w-2xl mb-8 text-left">
                <h3 className="font-semibold text-red-400 mb-3">Development Error Details</h3>
                <pre className="text-xs text-gray-300 overflow-auto">
                  {err.stack || err.message || 'Unknown error'}
                </pre>
              </div>
            )}

            {/* Silk Road Themed Message */}
            <div className="bg-gray-800 rounded-lg p-6 max-w-lg mb-8">
              <div className="flex items-center space-x-3 mb-3">
                <div className="w-8 h-8 bg-red-600 rounded-full flex items-center justify-center">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                  </svg>
                </div>
                <h3 className="font-semibold text-red-400">Trouble on the Digital Silk Road</h3>
              </div>
              <p className="text-sm text-gray-300">
                {statusCode === 500 
                  ? "Our servers are experiencing some turbulence. The technical caravan is working to restore normal operations."
                  : statusCode === 503
                  ? "The marketplace is temporarily closed for maintenance. Please check back shortly."
                  : "Something unexpected happened during your journey through our marketplace."
                }
              </p>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap gap-4 justify-center mb-8">
              <button
                onClick={() => window.location.reload()}
                className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors"
              >
                🔄 Try Again
              </button>
              
              <Link 
                href="/"
                className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors"
              >
                🏠 Go Home
              </Link>

              {statusCode === 401 && (
                <Link 
                  href="/login"
                  className="bg-green-600 hover:bg-green-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors"
                >
                  🔐 Login
                </Link>
              )}

              <button
                onClick={() => window.history.back()}
                className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors"
              >
                ← Go Back
              </button>
            </div>

            {/* Status-specific suggestions */}
            {statusCode === 500 && (
              <div className="bg-yellow-900/20 border border-yellow-500/30 rounded-lg p-4 max-w-lg">
                <h3 className="font-semibold text-yellow-400 mb-2">What you can do:</h3>
                <ul className="text-sm text-gray-300 space-y-1">
                  <li>• Wait a few minutes and try again</li>
                  <li>• Check our status page for known issues</li>
                  <li>• Clear your browser cache and cookies</li>
                  <li>• Contact support if the problem persists</li>
                </ul>
              </div>
            )}

            {statusCode === 503 && (
              <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4 max-w-lg">
                <h3 className="font-semibold text-blue-400 mb-2">Service Maintenance</h3>
                <p className="text-sm text-gray-300">
                  We're performing scheduled maintenance to improve your experience. 
                  Normal service will resume shortly.
                </p>
              </div>
            )}

            {/* Help Section */}
            <div className="mt-12 text-center">
              <p className="text-gray-400 mb-4">Need additional assistance?</p>
              <div className="flex flex-wrap justify-center gap-4">
                <Link 
                  href="/help"
                  className="text-purple-400 hover:text-purple-300 underline"
                >
                  Help Center
                </Link>
                <Link 
                  href="/contact"
                  className="text-purple-400 hover:text-purple-300 underline"
                >
                  Contact Support
                </Link>
                <Link 
                  href="/status"
                  className="text-purple-400 hover:text-purple-300 underline"
                >
                  System Status
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

CustomError.getInitialProps = ({ res, err }: NextPageContext) => {
  const statusCode = res ? res.statusCode : err ? err.statusCode : 404;
  return { statusCode };
};

export default CustomError;
