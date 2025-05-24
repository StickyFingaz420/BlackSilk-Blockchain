import { useEffect, useRef } from 'react';
import { createNodeWebSocket, closeNodeWebSocket } from './ws';

// Usage: useOrderStatusUpdates(orderId, callback)
export function useOrderStatusUpdates(orderId: string, onUpdate: (status: any) => void) {
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!orderId) return;
    wsRef.current = createNodeWebSocket((msg) => {
      if (msg.type === 'order_update' && msg.orderId === orderId) {
        onUpdate(msg.status);
      }
    });
    return () => {
      closeNodeWebSocket();
    };
  }, [orderId, onUpdate]);
}
