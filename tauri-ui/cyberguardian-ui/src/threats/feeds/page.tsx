"use client";

import { useState, useEffect } from "react";
import {
  RefreshCw,
  Activity,
  Database,
  CheckCircle,
  XCircle,
  ExternalLink,
  Shield,
  Key,
  Sparkles,
} from "lucide-react";
import ProtectedRoute from '@/components/ProtectedRoute';

// API configuration
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// Helper to make authenticated requests
const fetchWithAuth = async (endpoint: string, options?: RequestInit) => {
  const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      ...headers,
      ...(options?.headers || {}),
    }
  });
  return response.json();
};

interface Feed {
  id: number;
  name: string;
  type: string;
  enabled: boolean;
  url: string;
  last_update: string;
  status: string;
  ioc_count: number;
  api_key_required: boolean;
  description: string;
}

interface FeedStats {
  total_feeds: number;
  active_feeds: number;
  inactive_feeds: number;
  total_iocs: number;
}

export default function ThreatFeedsPage() {
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [stats, setStats] = useState<FeedStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshingId, setRefreshingId] = useState<number | null>(null);

  useEffect(() => {
    fetchFeeds();
  }, []);

  const fetchFeeds = async () => {
    setLoading(true);
    try {
      const data = await fetchWithAuth('/api/threat-intel/feeds');

      if (data.success) {
        setFeeds(data.feeds);
        setStats(data.statistics);
      }
    } catch (error) {
      console.error("Failed to fetch feeds:", error);
    } finally {
      setLoading(false);
    }
  };

  const toggleFeed = async (feedId: number) => {
    try {
      const data = await fetchWithAuth(`/api/threat-intel/feeds/${feedId}/toggle`, {
  method: "POST"
});

      if (data.success) {
        await fetchFeeds();
      }
    } catch (error) {
      console.error("Failed to toggle feed:", error);
    }
  };

  const refreshFeed = async (feedId: number) => {
    setRefreshingId(feedId);
    try {
      const data = await fetchWithAuth(`/api/threat-intel/feeds/${feedId}/refresh`, {
  method: "POST"
});

      if (data.success) {
        await fetchFeeds();
      }
    } catch (error) {
      console.error("Failed to refresh feed:", error);
    } finally {
      setRefreshingId(null);
    }
  };

  const formatDate = (dateString: string) => {
    if (!dateString) return "N/A";
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return "N/A";

    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);

    if (diffMins < 60) return `${diffMins} minutes ago`;
    if (diffHours < 24) return `${diffHours} hours ago`;
    return date.toLocaleDateString();
  };

  const formatNumber = (num: number) =>
    new Intl.NumberFormat().format(num ?? 0);

  if (loading) {
    return (
      <ProtectedRoute>
      <div className="p-6 space-y-6">
        <div className="animate-pulse space-y-6">
          <div className="h-12 bg-gray-800/50 rounded w-64" />
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-32 bg-gray-800/50 rounded-xl" />
            ))}
          </div>
        </div>
      </div>
      </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute>
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent flex items-center gap-3">
            <Database className="w-8 h-8 text-cyan-400" />
            Threat Intelligence Feeds
          </h1>
          <p className="text-gray-400 mt-1">
            Manage external threat intelligence sources
          </p>
        </div>

        <button
          onClick={fetchFeeds}
          className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg 
                     transition-all duration-300 flex items-center gap-2
                     hover:scale-105 hover:shadow-lg hover:shadow-cyan-500/50"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh All
        </button>
      </div>

      {/* Statistics */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="bg-gradient-to-br from-cyan-500/10 to-cyan-500/5 border border-cyan-500/20 
                        rounded-xl p-6 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-cyan-500/30
                        group cursor-pointer relative overflow-hidden">
            <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-white/5 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-cyan-500/10 rounded-lg transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-cyan-500/50">
                <Database className="w-6 h-6 text-cyan-400 transition-transform duration-300 group-hover:rotate-12" />
              </div>
            </div>
            <p className="text-gray-400 text-sm mb-1 transition-colors duration-300 group-hover:text-gray-300">Total Feeds</p>
            <p className="text-3xl font-bold text-cyan-400 transition-all duration-300 group-hover:scale-110 origin-left">
              {stats.total_feeds}
            </p>
          </div>

          <div className="bg-gradient-to-br from-green-500/10 to-green-500/5 border border-green-500/20 
                        rounded-xl p-6 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-green-500/30
                        group cursor-pointer relative overflow-hidden">
            <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-white/5 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-green-500/10 rounded-lg transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-green-500/50">
                <CheckCircle className="w-6 h-6 text-green-400 transition-transform duration-300 group-hover:rotate-12" />
              </div>
            </div>
            <p className="text-gray-400 text-sm mb-1 transition-colors duration-300 group-hover:text-gray-300">Active Feeds</p>
            <p className="text-3xl font-bold text-green-400 transition-all duration-300 group-hover:scale-110 origin-left">
              {stats.active_feeds}
            </p>
            
            {/* Pulse indicator */}
            {stats.active_feeds > 0 && (
              <div className="absolute top-4 right-4 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
              </div>
            )}
          </div>

          <div className="bg-gradient-to-br from-orange-500/10 to-orange-500/5 border border-orange-500/20 
                        rounded-xl p-6 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-orange-500/30
                        group cursor-pointer relative overflow-hidden">
            <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-white/5 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-orange-500/10 rounded-lg transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-orange-500/50">
                <XCircle className="w-6 h-6 text-orange-400 transition-transform duration-300 group-hover:rotate-12" />
              </div>
            </div>
            <p className="text-gray-400 text-sm mb-1 transition-colors duration-300 group-hover:text-gray-300">Inactive Feeds</p>
            <p className="text-3xl font-bold text-orange-400 transition-all duration-300 group-hover:scale-110 origin-left">
              {stats.inactive_feeds}
            </p>
          </div>

          <div className="bg-gradient-to-br from-purple-500/10 to-purple-500/5 border border-purple-500/20 
                        rounded-xl p-6 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/30
                        group cursor-pointer relative overflow-hidden">
            <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-white/5 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-purple-500/10 rounded-lg transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-purple-500/50">
                <Shield className="w-6 h-6 text-purple-400 transition-transform duration-300 group-hover:rotate-12" />
              </div>
            </div>
            <p className="text-gray-400 text-sm mb-1 transition-colors duration-300 group-hover:text-gray-300">Total IOCs</p>
            <p className="text-3xl font-bold text-purple-400 transition-all duration-300 group-hover:scale-110 origin-left">
              {formatNumber(stats.total_iocs)}
            </p>
          </div>
        </div>
      )}

      {/* Auto-Update Status */}
      <div className="bg-gradient-to-r from-purple-500/10 to-cyan-500/10 border border-purple-500/30 
                    rounded-xl p-4 flex items-center justify-between
                    transition-all duration-300 hover:border-purple-500/50 hover:shadow-lg hover:shadow-purple-500/20
                    group relative overflow-hidden">
        {/* Animated background */}
        <div className="absolute inset-0 bg-gradient-to-r from-purple-500/5 to-cyan-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
        
        <div className="flex items-center gap-3 relative z-10">
          <div className="p-2 bg-purple-500/20 rounded-lg transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-purple-500/50">
            <RefreshCw className="w-5 h-5 text-purple-400 transition-transform duration-300 group-hover:rotate-180" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white transition-colors duration-300 group-hover:text-purple-300">
              Automated Intelligence Updates
            </h3>
            <p className="text-xs text-gray-400 transition-colors duration-300 group-hover:text-gray-300">
              Updates run every 6 hours automatically
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 relative z-10">
          <div className="h-2 w-2 rounded-full bg-green-400 animate-pulse"></div>
          <span className="text-sm text-green-400 font-medium transition-all duration-300 group-hover:scale-105">Active</span>
        </div>
      </div>

      {/* Feed Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {feeds.map((feed) => (
          <div
            key={feed.id}
            className={`
              bg-gray-800/50 border rounded-xl p-6 
              transition-all duration-300 hover:shadow-lg
              group relative overflow-hidden
              ${feed.enabled
                ? "border-cyan-500/30 hover:border-cyan-500/50 hover:shadow-cyan-500/20"
                : "border-gray-700 hover:border-gray-600 hover:shadow-gray-500/20"
              }
            `}
          >
            {/* Corner glow */}
            <div className={`absolute top-0 right-0 w-24 h-24 bg-gradient-to-br from-white/5 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-300`} />
            
            {/* Feed Header */}
            <div className="flex items-start justify-between mb-4 relative z-10">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2 flex-wrap">
                  <h3 className="text-xl font-bold text-white transition-colors duration-300 group-hover:text-cyan-400">
                    {feed.name}
                  </h3>
                  {feed.enabled ? (
                    <span className="px-2 py-1 bg-green-500/20 border border-green-500/30 
                                   rounded text-xs text-green-400 font-medium
                                   transition-all duration-300 group-hover:scale-105 group-hover:shadow-lg group-hover:shadow-green-500/50
                                   relative">
                      Active
                      <span className="absolute -top-1 -right-1 flex h-2 w-2">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                      </span>
                    </span>
                  ) : (
                    <span className="px-2 py-1 bg-gray-500/20 border border-gray-500/30 
                                   rounded text-xs text-gray-400 font-medium
                                   transition-all duration-300 group-hover:scale-105">
                      Inactive
                    </span>
                  )}
                  {feed.api_key_required && (
                    <div className="p-1 bg-yellow-500/20 rounded transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-yellow-500/50" title="API Key Required">
                      <Key className="w-4 h-4 text-yellow-400" />
                    </div>
                  )}
                </div>
                <p className="text-sm text-gray-400 transition-colors duration-300 group-hover:text-gray-300">
                  {feed.description}
                </p>
              </div>
            </div>

            {/* Feed Stats */}
            <div className="grid grid-cols-2 gap-4 mb-4 p-4 bg-gray-900/50 rounded-lg border border-gray-700/50 transition-all duration-300 group-hover:border-cyan-500/30 group-hover:bg-gray-900/70">
              <div>
                <p className="text-xs text-gray-400 mb-1 transition-colors duration-300 group-hover:text-gray-300">IOC Count</p>
                <p className="text-lg font-bold text-white transition-all duration-300 group-hover:text-cyan-400 group-hover:scale-105 origin-left">
                  {formatNumber(feed.ioc_count)}
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-400 mb-1 transition-colors duration-300 group-hover:text-gray-300">Type</p>
                <p className="text-sm font-medium text-cyan-400 transition-all duration-300 group-hover:scale-105 origin-left">
                  {feed.type}
                </p>
              </div>
            </div>

            {/* Last Update */}
            <div className="flex items-center gap-2 text-sm text-gray-400 mb-4 transition-colors duration-300 group-hover:text-gray-300">
              <Activity className="w-4 h-4 transition-transform duration-300 group-hover:scale-110" />
              <span>Last updated: {formatDate(feed.last_update)}</span>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-3">
              <button
                onClick={() => toggleFeed(feed.id)}
                className={`
                  flex-1 px-4 py-2 rounded-lg font-medium transition-all duration-300
                  hover:scale-105 hover:shadow-lg
                  ${feed.enabled
                    ? "bg-red-500/20 border border-red-500/30 text-red-400 hover:bg-red-500/30 hover:shadow-red-500/50"
                    : "bg-green-500/20 border border-green-500/30 text-green-400 hover:bg-green-500/30 hover:shadow-green-500/50"
                  }
                `}
              >
                {feed.enabled ? "Disable" : "Enable"}
              </button>

              <button
                onClick={() => refreshFeed(feed.id)}
                disabled={!feed.enabled || refreshingId === feed.id}
                className="px-4 py-2 bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 
                         rounded-lg font-medium transition-all duration-300 
                         hover:bg-cyan-500/30 hover:scale-105 hover:shadow-lg hover:shadow-cyan-500/50
                         disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 disabled:hover:shadow-none
                         flex items-center gap-2"
              >
                <RefreshCw
                  className={`w-4 h-4 transition-transform duration-300 ${
                    refreshingId === feed.id ? "animate-spin" : "group-hover:rotate-180"
                  }`}
                />
                Refresh
              </button>

              <a
                href={feed.url}
                target="_blank"
                rel="noopener noreferrer"
                className="px-4 py-2 bg-gray-700/50 border border-gray-600 text-gray-300 
                         rounded-lg font-medium transition-all duration-300 
                         hover:bg-gray-700 hover:scale-105 hover:shadow-lg hover:shadow-gray-500/50
                         flex items-center gap-2"
              >
                <ExternalLink className="w-4 h-4 transition-transform duration-300 group-hover:translate-x-1 group-hover:-translate-y-1" />
                View
              </a>
            </div>
          </div>
        ))}
      </div>

      {/* Empty State */}
      {feeds.length === 0 && !loading && (
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-12 text-center relative overflow-hidden">
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div className="absolute top-1/4 left-1/4 w-32 h-32 bg-cyan-500/5 rounded-full blur-3xl animate-float" />
            <div className="absolute bottom-1/4 right-1/4 w-40 h-40 bg-purple-500/5 rounded-full blur-3xl animate-float-delayed" />
          </div>

          <div className="relative z-10">
            <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-gradient-to-br from-cyan-500/20 to-purple-500/20 mb-6 animate-pulse">
              <Database className="w-10 h-10 text-cyan-400" />
            </div>
            
            <h3 className="text-xl font-bold text-white mb-2 bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
              No Threat Feeds Configured
            </h3>
            
            <p className="text-gray-400 mb-6 max-w-md mx-auto">
              Configure threat intelligence feeds to start receiving IOCs and threat data.
            </p>

            <button className="px-4 py-2 bg-cyan-500/20 border border-cyan-500/30 rounded-lg text-cyan-400
                       transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-cyan-500/50
                       flex items-center gap-2 mx-auto">
              <Sparkles className="w-4 h-4" />
              Configure Feeds
            </button>
          </div>
        </div>
      )}
    </div>
      </ProtectedRoute>
  );
}