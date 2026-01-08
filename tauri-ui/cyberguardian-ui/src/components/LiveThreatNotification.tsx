"use client";

import { useEffect, useState } from 'react';
import { X, AlertTriangle, Shield } from 'lucide-react';

interface ThreatNotification {
  id: string;
  title: string;
  severity: string;
  timestamp: string;
}

interface LiveThreatNotificationProps {
  threat: ThreatNotification | null;
  onClose: () => void;
}

export function LiveThreatNotification({ threat, onClose }: LiveThreatNotificationProps) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (threat) {
      setVisible(true);
      
      // Auto-close after 10 seconds
      const timer = setTimeout(() => {
        setVisible(false);
        setTimeout(onClose, 300); // Wait for animation
      }, 10000);

      return () => clearTimeout(timer);
    }
  }, [threat, onClose]);

  if (!threat) return null;

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-500/20 border-red-500/50 text-red-400';
      case 'high': return 'bg-orange-500/20 border-orange-500/50 text-orange-400';
      case 'medium': return 'bg-yellow-500/20 border-yellow-500/50 text-yellow-400';
      default: return 'bg-blue-500/20 border-blue-500/50 text-blue-400';
    }
  };

  return (
    <div
      className={`fixed top-20 right-6 z-50 transition-all duration-300 ${
        visible ? 'translate-x-0 opacity-100' : 'translate-x-full opacity-0'
      }`}
    >
      <div className={`${getSeverityColor(threat.severity)} border rounded-xl p-4 shadow-2xl backdrop-blur-sm min-w-[350px] max-w-md`}>
        <div className="flex items-start gap-3">
          <div className="p-2 bg-current/20 rounded-lg">
            <AlertTriangle className="w-5 h-5" />
          </div>
          
          <div className="flex-1">
            <div className="flex items-center justify-between mb-1">
              <h4 className="font-semibold">🚨 New Threat Detected</h4>
              <button
                onClick={() => {
                  setVisible(false);
                  setTimeout(onClose, 300);
                }}
                className="p-1 hover:bg-white/10 rounded transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            
            <p className="text-sm opacity-90 mb-2">{threat.title}</p>
            
            <div className="flex items-center gap-2 text-xs opacity-70">
              <span className="uppercase font-semibold">{threat.severity}</span>
              <span>•</span>
              <span>{new Date(threat.timestamp).toLocaleTimeString()}</span>
            </div>
          </div>
        </div>
        
        <div className="mt-3 flex gap-2">
          <button className="flex-1 px-3 py-1.5 bg-white/10 hover:bg-white/20 rounded-lg text-sm font-medium transition-colors">
            View Details
          </button>
          <button className="flex-1 px-3 py-1.5 bg-red-500/30 hover:bg-red-500/40 rounded-lg text-sm font-medium transition-colors">
            Block Threat
          </button>
        </div>
      </div>
    </div>
  );
}