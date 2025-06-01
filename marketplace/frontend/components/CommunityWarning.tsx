import React, { useState } from 'react';

interface CommunityWarningProps {
  onAccept: () => void;
  onDecline: () => void;
}

export const CommunityWarning: React.FC<CommunityWarningProps> = ({ onAccept, onDecline }) => {
  return (
    <div className="fixed inset-0 bg-black/90 flex items-center justify-center z-50 p-4">
      <div className="bg-gradient-to-b from-amber-900/20 to-black border border-amber-600/50 rounded-lg max-w-2xl w-full p-8 text-center">
        <div className="text-6xl mb-6">⚠️</div>
        
        <h2 className="text-amber-300 text-2xl font-bold mb-6">
          Community Standards Notice
        </h2>
        
        <div className="text-gray-300 space-y-4 mb-8 text-left">
          <p className="text-center text-xl font-semibold text-red-400 mb-6">
            "Don't be sick"
          </p>
          
          <p>
            Welcome to the BlackSilk Marketplace. This is a <strong>privacy-first, decentralized marketplace</strong> built on blockchain technology that respects your anonymity and freedom.
          </p>
          
          <p>
            However, with great freedom comes great responsibility. We maintain community standards to ensure this platform remains safe and lawful for all users.
          </p>
          
          <div className="bg-red-900/20 border border-red-700/50 rounded-lg p-4">
            <h3 className="text-red-300 font-semibold mb-2">Prohibited Content:</h3>
            <ul className="text-sm space-y-1 text-gray-300">
              <li>• Pornographic or sexually explicit material</li>
              <li>• Content involving minors in any inappropriate context</li>
              <li>• Illegal weapons, drugs, or contraband</li>
              <li>• Stolen goods or fraudulent services</li>
              <li>• Content that promotes violence or harm</li>
              <li>• Doxxing or harassment materials</li>
            </ul>
          </div>
          
          <div className="bg-amber-900/20 border border-amber-700/50 rounded-lg p-4">
            <h3 className="text-amber-300 font-semibold mb-2">What We Support:</h3>
            <ul className="text-sm space-y-1 text-gray-300">
              <li>• Digital goods and legitimate software</li>
              <li>• Professional services and consultations</li>
              <li>• Art, media, and creative content</li>
              <li>• Educational materials and courses</li>
              <li>• Privacy tools and security services</li>
              <li>• Physical goods that are legal to trade</li>
            </ul>
          </div>
          
          <p className="text-center text-sm text-gray-400">
            Violations are reported to our decentralized moderation system and may result in content removal and account restrictions.
          </p>
        </div>
        
        <div className="flex gap-4">
          <button
            onClick={onDecline}
            className="flex-1 bg-red-900/50 hover:bg-red-800/50 text-red-300 px-6 py-3 rounded-lg font-semibold transition-colors"
          >
            I Disagree - Exit
          </button>
          
          <button
            onClick={onAccept}
            className="flex-1 bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 px-6 py-3 rounded-lg font-semibold transition-colors"
          >
            I Agree - Continue
          </button>
        </div>
        
        <div className="mt-4 text-xs text-gray-500">
          By continuing, you acknowledge that you understand and will comply with these community standards.
        </div>
      </div>
    </div>
  );
};

interface PrivacyIndicatorProps {
  level: 'standard' | 'enhanced' | 'maximum';
  className?: string;
}

export const PrivacyIndicator: React.FC<PrivacyIndicatorProps> = ({ level, className = '' }) => {
  const getPrivacyConfig = () => {
    switch (level) {
      case 'maximum':
        return {
          color: 'text-green-400',
          bg: 'bg-green-900/20',
          border: 'border-green-700/50',
          icon: '🛡️',
          text: 'Maximum Privacy',
          description: 'Tor + I2P + Stealth Addresses'
        };
      case 'enhanced':
        return {
          color: 'text-amber-400',
          bg: 'bg-amber-900/20',
          border: 'border-amber-700/50',
          icon: '🔒',
          text: 'Enhanced Privacy',
          description: 'Tor Network + Anonymous Routing'
        };
      default:
        return {
          color: 'text-blue-400',
          bg: 'bg-blue-900/20',
          border: 'border-blue-700/50',
          icon: '🔐',
          text: 'Standard Privacy',
          description: 'Encrypted + Pseudonymous'
        };
    }
  };

  const config = getPrivacyConfig();

  return (
    <div className={`${config.bg} ${config.border} border rounded-lg p-3 ${className}`}>
      <div className="flex items-center space-x-2">
        <span className="text-lg">{config.icon}</span>
        <div>
          <div className={`${config.color} font-semibold text-sm`}>
            {config.text}
          </div>
          <div className="text-xs text-gray-400">
            {config.description}
          </div>
        </div>
      </div>
    </div>
  );
};

export default CommunityWarning;
