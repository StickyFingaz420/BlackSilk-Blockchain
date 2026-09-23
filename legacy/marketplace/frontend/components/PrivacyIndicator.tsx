import React from 'react';
import { PrivacyLevel } from '../types';

interface PrivacyIndicatorProps {
  level?: PrivacyLevel;
  className?: string;
}

export const PrivacyIndicator: React.FC<PrivacyIndicatorProps> = ({ 
  level = PrivacyLevel.Maximum, 
  className = '' 
}) => {
  const getIndicatorConfig = () => {
    switch (level) {
      case PrivacyLevel.Low:
        return {
          color: 'text-red-400',
          bg: 'bg-red-900/20',
          border: 'border-red-800/30',
          icon: '🔓',
          text: 'Low Privacy'
        };
      case PrivacyLevel.Medium:
        return {
          color: 'text-yellow-400',
          bg: 'bg-yellow-900/20',
          border: 'border-yellow-800/30',
          icon: '🔐',
          text: 'Medium Privacy'
        };
      case PrivacyLevel.High:
        return {
          color: 'text-green-400',
          bg: 'bg-green-900/20',
          border: 'border-green-800/30',
          icon: '🔒',
          text: 'High Privacy'
        };
      case PrivacyLevel.Maximum:
      default:
        return {
          color: 'text-purple-400',
          bg: 'bg-purple-900/20',
          border: 'border-purple-800/30',
          icon: '🛡️',
          text: 'Maximum Privacy'
        };
    }
  };

  const config = getIndicatorConfig();

  return (
    <div className={`flex items-center px-3 py-1 rounded-full border ${config.bg} ${config.border} ${className}`}>
      <span className="mr-2">{config.icon}</span>
      <span className={`text-sm font-medium ${config.color}`}>
        {config.text}
      </span>
    </div>
  );
};

export default PrivacyIndicator;
