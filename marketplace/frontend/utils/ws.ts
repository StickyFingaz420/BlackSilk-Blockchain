// Utility for connecting to BlackSilk node WebSocket API
// Usage: const ws = createNodeWebSocket(onMessage)

let ws: WebSocket | null = null;

export function createNodeWebSocket(onMessage: (msg: any) => void): WebSocket {
  const NODE_WS = process.env.NEXT_PUBLIC_NODE_WS_URL || 'ws://localhost:1776/ws';
  // Enforce WSS for clearnet, allow ws for localhost/.onion/.i2p
  if (!NODE_WS.startsWith('ws://localhost') && !NODE_WS.startsWith('wss://') && !NODE_WS.includes('.onion') && !NODE_WS.includes('.i2p')) {
    throw new Error('Insecure WebSocket endpoint: use WSS, .onion, or .i2p');
  }
  ws = new window.WebSocket(NODE_WS);
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch {}
  };
  ws.onclose = () => {
    // Optionally: reconnect logic
  };
  return ws;
}

export function closeNodeWebSocket() {
  if (ws) ws.close();
  ws = null;
}
