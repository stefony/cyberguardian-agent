"use client";

import React, { createContext, useContext, ReactNode } from 'react';
import { useWebSocket } from '../useWebSocket';

type WebSocketMessage = {
  type: string;
  data?: any;
  timestamp?: string;
};

type WebSocketContextType = {
  isConnected: boolean;
  lastMessage: WebSocketMessage | null;
  sendMessage: (message: any) => void;
};

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export function WebSocketProvider({ children }: { children: ReactNode }) {
  // Determine WebSocket URL based on environment
  const getWebSocketUrl = () => {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || '${process.env.NEXT_PUBLIC_API_URL}';
    const wsProtocol = apiUrl.startsWith('https') ? 'wss' : 'ws';
    const wsHost = apiUrl.replace('http://', '').replace('https://', '');
    return `${wsProtocol}://${wsHost}/api/ws/connect`;
  };

  const { isConnected, lastMessage, sendMessage } = useWebSocket(
    getWebSocketUrl(),
    true // auto-connect
  );

  return (
    <WebSocketContext.Provider value={{ isConnected, lastMessage, sendMessage }}>
      {children}
    </WebSocketContext.Provider>
  );
}

export function useWebSocketContext() {
  const context = useContext(WebSocketContext);
  if (context === undefined) {
    throw new Error('useWebSocketContext must be used within WebSocketProvider');
  }
  return context;
}