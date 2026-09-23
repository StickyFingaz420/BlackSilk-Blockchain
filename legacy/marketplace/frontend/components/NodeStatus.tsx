import React from 'react';
import { useNodeStatus } from '../hooks';

export const NodeStatus: React.FC = () => {
  const { nodeInfo, isOnline, isLoading } = useNodeStatus();

  if (isLoading) {
    return (
      <div className="bg-black/40 border border-amber-800/30 rounded-lg p-4">
        <div className="animate-pulse flex items-center">
          <div className="w-3 h-3 bg-gray-600 rounded-full mr-3"></div>
          <div className="text-gray-400">Checking node status...</div>
        </div>
      </div>
    );
  }

  if (!isOnline) {
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

  if (!nodeInfo) {
    return (
      <div className="bg-black/40 border border-yellow-800/30 rounded-lg p-4">
        <div className="flex items-center">
          <div className="w-3 h-3 bg-yellow-500 rounded-full mr-3"></div>
          <div className="text-yellow-400">Node Info Unavailable</div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-black/40 border border-green-800/30 rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center">
          <div className="w-3 h-3 bg-green-500 rounded-full mr-3"></div>
          <div className="font-medium text-green-400">
            Synchronized
          </div>
        </div>
        <div className="text-xs text-gray-500">
          🔒 Privacy Mode
        </div>
      </div>
      
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <div className="text-gray-400">Block Height</div>
          <div className="text-white font-mono">
            {nodeInfo.chain_height?.toLocaleString() || 'Unknown'}
          </div>
        </div>
        <div>
          <div className="text-gray-400">Peers</div>
          <div className="text-white font-mono">
            {nodeInfo.peers || 0}
          </div>
        </div>
        <div>
          <div className="text-gray-400">Hash Rate</div>
          <div className="text-white font-mono">
            {nodeInfo.hashrate ? `${(nodeInfo.hashrate / 1000000).toFixed(2)} MH/s` : 'N/A'}
          </div>
        </div>
        <div>
          <div className="text-gray-400">Difficulty</div>
          <div className="text-white font-mono">
            {nodeInfo.difficulty ? nodeInfo.difficulty.toExponential(2) : 'N/A'}
          </div>
        </div>
      </div>

      <div className="mt-3 pt-3 border-t border-gray-700 text-xs text-gray-400 space-y-1">
        <div className="flex justify-between">
          <span>Network: {nodeInfo.network || 'BlackSilk'}</span>
        </div>
        <div className="flex justify-between">
          <span>Privacy: Enhanced</span>
        </div>
      </div>
    </div>
  );
};

export default NodeStatus;
