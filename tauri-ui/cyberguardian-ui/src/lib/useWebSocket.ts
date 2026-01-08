"use client";

import { useEffect, useRef, useState, useCallback } from 'react';

type WebSocketMessage = {
  type: string;
  data?: any;
  timestamp?: string;
  status?: string;
  message?: string;
};

type WebSocketHookReturn = {
  isConnected: boolean;
  lastMessage: WebSocketMessage | null;
  sendMessage: (message: any) => void;
  connect: () => void;
  disconnect: () => void;
};

export function useWebSocket(url: string, autoConnect: boolean = true): WebSocketHookReturn {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      console.log('WebSocket already connected');
      return;
    }

    try {
      console.log('🔌 Connecting to WebSocket:', url);
      const ws = new WebSocket(url);

      ws.onopen = () => {
        console.log('✅ WebSocket connected');
        setIsConnected(true);
        reconnectAttempts.current = 0;

        // Send initial ping
        ws.send(JSON.stringify({ type: 'ping' }));
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          console.log('📨 WebSocket message:', message);
          setLastMessage(message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      ws.onerror = (event) => {
  console.warn('⚠️ WebSocket error (non-fatal):', {
    type: event?.type ?? 'error',
    url: ws.url,
    readyState: ws.readyState // 0=CONNECTING, 1=OPEN, 2=CLOSING, 3=CLOSED
  });
};

ws.onclose = () => {
  console.warn('🔌 WebSocket disconnected');
  setIsConnected(false);
  wsRef.current = null;

  // Auto-reconnect
  if (reconnectAttempts.current < maxReconnectAttempts) {
    reconnectAttempts.current++;
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
    console.log(`🔄 Reconnecting in ${delay}ms (attempt ${reconnectAttempts.current})`);

    reconnectTimeoutRef.current = setTimeout(() => {
      connect();
    }, delay);
  } else {
    console.error('⛔ Max reconnect attempts reached — WS stopped trying.');
  }
};

      wsRef.current = ws;
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
    }
  }, [url]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    
    if (wsRef.current) {
      console.log('👋 Manually disconnecting WebSocket');
      wsRef.current.close();
      wsRef.current = null;
    }
    
    setIsConnected(false);
  }, []);

  const sendMessage = useCallback((message: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket is not connected. Cannot send message.');
    }
  }, []);

  useEffect(() => {
    if (autoConnect) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [autoConnect, connect, disconnect]);

  // Heartbeat - send ping every 30 seconds
  useEffect(() => {
    if (!isConnected) return;

    const interval = setInterval(() => {
      sendMessage({ type: 'ping' });
    }, 30000);

    return () => clearInterval(interval);
  }, [isConnected, sendMessage]);

  return {
    isConnected,
    lastMessage,
    sendMessage,
    connect,
    disconnect,
  };
}