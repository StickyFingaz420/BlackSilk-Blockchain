import React from 'react';
import { useNodeStatus } from '../hooks';

export const NodeStatus: React.FC = () => {
  const { nodeStatus, loading, error } = useNodeStatus();

  if (loading) {
    return (
      <div className="bg-black/40 border border-amber-800/30 rounded-lg p-4">
        <div className="animate-pulse flex items-center">
          <div className="w-3 h-3 bg-gray-600 rounded-full mr-3"></div>
          <div className="text-gray-400">Checking node status...</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-black/40 border border-red-800/30 rounded-lg p-4">
        <div className="flex items-center">
          <div className="w-3 h-3 bg-red-500 rounded-full mr-3 animate-pulse"></div>
          <div className="text-red-400">Node Offline</div>
        </div>
        <div className="text-xs text-gray-500 mt-1">
          Unable to connect to BlackSilk node
        </div>
      </div>
    );
  }

  if (!nodeStatus) {
    return null;
  }

  const getStatusColor = () => {
    if (nodeStatus.synced) return 'text-green-400';
    if (nodeStatus.connected) return 'text-yellow-400';
    return 'text-red-400';
  };

  const getStatusDot = () => {
    if (nodeStatus.synced) return 'bg-green-500';
    if (nodeStatus.connected) return 'bg-yellow-500 animate-pulse';
    return 'bg-red-500 animate-pulse';
  };

  const getStatusText = () => {
    if (nodeStatus.synced) return 'Synchronized';
    if (nodeStatus.connected) return 'Synchronizing...';
    return 'Disconnected';
  };

  return (
    <div className="bg-black/40 border border-amber-800/30 rounded-lg p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          <div className={`w-3 h-3 rounded-full mr-3 ${getStatusDot()}`}></div>
          <div className={`font-medium ${getStatusColor()}`}>
            {getStatusText()}
          </div>
        </div>
        
        {nodeStatus.synced && (
          <div className="text-xs text-gray-500">
            🔒 Privacy Mode
          </div>
        )}
      </div>

      <div className="mt-3 grid grid-cols-2 gap-4 text-sm">
        <div>
          <div className="text-gray-400">Block Height</div>
          <div className="text-amber-300 font-mono">
            {nodeStatus.blockHeight?.toLocaleString() || 'Unknown'}
          </div>
        </div>
        
        <div>
          <div className="text-gray-400">Connections</div>
          <div className="text-amber-300 font-mono">
            {nodeStatus.connections || 0}
          </div>
        </div>
        
        <div>
          <div className="text-gray-400">Hash Rate</div>
          <div className="text-amber-300 font-mono">
            {nodeStatus.hashRate ? `${(nodeStatus.hashRate / 1000000).toFixed(2)} MH/s` : 'N/A'}
          </div>
        </div>
        
        <div>
          <div className="text-gray-400">Difficulty</div>
          <div className="text-amber-300 font-mono">
            {nodeStatus.difficulty ? nodeStatus.difficulty.toExponential(2) : 'N/A'}
          </div>
        </div>
      </div>

      {nodeStatus.version && (
        <div className="mt-3 pt-3 border-t border-amber-800/20">
          <div className="text-xs text-gray-500 flex justify-between">
            <span>BlackSilk Node v{nodeStatus.version}</span>
            <span>Privacy: {nodeStatus.privacyMode ? 'Enhanced' : 'Standard'}</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default NodeStatus;
