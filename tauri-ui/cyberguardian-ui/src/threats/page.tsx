"use client";

import { Shield, AlertTriangle, TrendingUp, Filter, RefreshCw, Ban, X, Copy, CheckCircle2 } from "lucide-react";
import { threatsApi } from "@/lib/api";
import type { ThreatResponse, ThreatStats } from "@/lib/types";
import { useWebSocketContext } from "@/lib/contexts/WebSocketContext";
import { useEffect, useState, useCallback } from "react";
import ProtectedRoute from '@/components/ProtectedRoute';

// ✅ Add here
function normalizeThreatList(resp: any): ThreatResponse[] {
  if (Array.isArray(resp)) return resp as ThreatResponse[];
  if (Array.isArray(resp?.data)) return resp.data as ThreatResponse[];
  if (Array.isArray(resp?.data?.data)) return resp.data.data as ThreatResponse[];
  if (Array.isArray(resp?.items)) return resp.items as ThreatResponse[];
  if (Array.isArray(resp?.data?.items)) return resp.data.items as ThreatResponse[];
  return [];
}

export default function ThreatsPage() {
  const [threats, setThreats] = useState<ThreatResponse[]>([]);
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // WebSocket integration for live updates
  const { lastMessage } = useWebSocketContext();
  
  // Batch selection state
  const [selectedThreats, setSelectedThreats] = useState<Set<number>>(new Set());
  const [isSelectAll, setIsSelectAll] = useState(false);
  
  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  
  // 🆕 Copy to clipboard state
  const [copiedIp, setCopiedIp] = useState<string | null>(null);

  // Fetch threats with correlations
  const fetchThreats = useCallback(async () => {
    try {
      setIsLoading(true);

      // Build query params
      const params: Record<string, string> = {};
      if (severityFilter !== "all") params.severity = severityFilter;
      if (statusFilter !== "all") params.status = statusFilter;

      const response = await threatsApi.getThreats(params);

      // Handle ApiResponse wrapper
      if (response.success && response.data) {
        const items = Array.isArray(response.data) 
          ? response.data 
          : normalizeThreatList(response.data);
        
        // Fetch correlations for each threat
        const threatsWithCorrelations = await Promise.all(
          items.map(async (threat) => {
            try {
              const correlationResponse = await fetch(
                `${process.env.NEXT_PUBLIC_API_URL}/api/threats/${threat.id}/correlations`
              );
              const correlationData = await correlationResponse.json();
              
              return {
                ...threat,
                correlation: correlationData.success ? correlationData.correlations : null
              };
            } catch (err) {
              console.error(`Failed to fetch correlations for threat ${threat.id}:`, err);
              return { ...threat, correlation: null };
            }
          })
        );
        
        setThreats(threatsWithCorrelations);
        setError(null);
      } else {
        setError(response.error || "Failed to load threats");
        setThreats([]);
      }

    } catch (err) {
      console.error("Error fetching threats:", err);
      setError("Could not load threats");
      setThreats([]);
    } finally {
      setIsLoading(false);
    }
  }, [severityFilter, statusFilter]);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    try {
      const response = await threatsApi.getStats();
      if (response.success && response.data) {
        setStats(response.data);
      }
    } catch (err) {
      console.error("Error fetching stats:", err);
    }
  }, []);

  // Block threat
  const blockThreat = async (threatId: number) => {
    try {
      const response = await threatsApi.blockThreat(threatId);
      
      if (response.success) {
        // Refresh threats
        await fetchThreats();
        await fetchStats();
      } else {
        alert(response.error || "Failed to block threat");
      }
    } catch (err) {
      console.error("Error blocking threat:", err);
      alert("Failed to block threat");
    }
  };

  // Dismiss threat
  const dismissThreat = async (threatId: number) => {
    try {
      const response = await threatsApi.dismissThreat(threatId);
      
      if (response.success) {
        // Refresh threats
        await fetchThreats();
        await fetchStats();
      } else {
        alert(response.error || "Failed to dismiss threat");
      }
    } catch (err) {
      console.error("Error dismissing threat:", err);
      alert("Failed to dismiss threat");
    }
  };

  // Initial load
  useEffect(() => {
    fetchStats();
    fetchThreats();
  }, [fetchStats, fetchThreats, severityFilter, statusFilter]);

  // Listen for live threat updates via WebSocket
  useEffect(() => {
    if (!lastMessage) return;
    
    if (lastMessage.type === 'threat_update') {
      console.log('🚨 New threat received via WebSocket!', lastMessage.data);
      
      // Refresh threats list
      fetchThreats();
      fetchStats();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastMessage]);

  // Format timestamp
  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
  };

  // Toggle select all
  const toggleSelectAll = () => {
    console.log('🔵 toggleSelectAll CALLED!');
    console.log('🔵 Current isSelectAll:', isSelectAll);
    console.log('🔵 Threats array:', threats);
    
    if (isSelectAll) {
      setSelectedThreats(new Set());
      setIsSelectAll(false);
    } else {
      const allIds = new Set(threats.map(t => t.id));
      console.log('🔵 All IDs:', Array.from(allIds));
      setSelectedThreats(allIds);
      setIsSelectAll(true);
    }
  };

  // Debug: Log when selection changes
  useEffect(() => {
    console.log('🔍 Selected Threats Size:', selectedThreats.size);
    console.log('🔍 Selected Threats IDs:', Array.from(selectedThreats));
  }, [selectedThreats]);

  // Toggle single threat selection
  const toggleThreatSelection = (threatId: number) => {
    const newSelected = new Set(selectedThreats);
    if (newSelected.has(threatId)) {
      newSelected.delete(threatId);
    } else {
      newSelected.add(threatId);
    }
    setSelectedThreats(newSelected);
    setIsSelectAll(newSelected.size === threats.length);
  };

  // Batch block threats
  const batchBlockThreats = async () => {
    if (selectedThreats.size === 0) return;
    
    if (!confirm(`Block ${selectedThreats.size} threats?`)) return;
    
    try {
      const response = await threatsApi.batchAction({
        threat_ids: Array.from(selectedThreats),
        action: 'block',
        reason: 'Bulk block action'
      });
      
      if (response.success) {
        await fetchThreats();
        await fetchStats();
        setSelectedThreats(new Set());
        setIsSelectAll(false);
      } else {
        alert(response.error || 'Failed to block threats');
      }
    } catch (err) {
      console.error('Batch block failed:', err);
      alert('Failed to block threats');
    }
  };

  // Batch dismiss threats
  const batchDismissThreats = async () => {
    if (selectedThreats.size === 0) return;
    
    if (!confirm(`Dismiss ${selectedThreats.size} threats?`)) return;
    
    try {
      const response = await threatsApi.batchAction({
        threat_ids: Array.from(selectedThreats),
        action: 'dismiss',
        reason: 'Bulk dismiss action'
      });
      
      if (response.success) {
        await fetchThreats();
        await fetchStats();
        setSelectedThreats(new Set());
        setIsSelectAll(false);
      } else {
        alert(response.error || 'Failed to dismiss threats');
      }
    } catch (err) {
      console.error('Batch dismiss failed:', err);
      alert('Failed to dismiss threats');
    }
  };

  // Batch delete threats
  const batchDeleteThreats = async () => {
    if (selectedThreats.size === 0) return;
    
    if (!confirm(`Permanently delete ${selectedThreats.size} threats? This cannot be undone!`)) return;
    
    try {
      const response = await threatsApi.batchAction({
        threat_ids: Array.from(selectedThreats),
        action: 'delete',
        reason: 'Bulk delete action'
      });
      
      if (response.success) {
        await fetchThreats();
        await fetchStats();
        setSelectedThreats(new Set());
        setIsSelectAll(false);
      } else {
        alert(response.error || 'Failed to delete threats');
      }
    } catch (err) {
      console.error('Batch delete failed:', err);
      alert('Failed to delete threats');
    }
  };

  // 🆕 Copy IP to clipboard
  const copyIpToClipboard = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  // Severity badge class
  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case "critical": return "badge badge--err";
      case "high": return "badge badge--warn";
      case "medium": return "badge badge--info";
      case "low": return "badge badge--ok";
      default: return "badge";
    }
  };

  // Status badge class
  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case "active": return "badge badge--err";
      case "blocked": return "badge badge--ok";
      case "dismissed": return "badge";
      default: return "badge";
    }
  };

  // 🆕 Get row hover gradient based on severity
  const getRowHoverGradient = (severity: string) => {
    switch (severity) {
      case "critical": 
        return "hover:bg-gradient-to-r hover:from-red-500/10 hover:via-red-500/5 hover:to-transparent";
      case "high": 
        return "hover:bg-gradient-to-r hover:from-orange-500/10 hover:via-orange-500/5 hover:to-transparent";
      case "medium": 
        return "hover:bg-gradient-to-r hover:from-yellow-500/10 hover:via-yellow-500/5 hover:to-transparent";
      case "low": 
        return "hover:bg-gradient-to-r hover:from-blue-500/10 hover:via-blue-500/5 hover:to-transparent";
      default: 
        return "hover:bg-gradient-to-r hover:from-purple-500/10 hover:via-purple-500/5 hover:to-transparent";
    }
  };

  return (
    <ProtectedRoute>
    <main className="pb-12">
      {/* Hero */}
      <div className="page-container page-hero pt-12 md:pt-16">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
              Threat Management
            </h1>
            <p className="mt-2 text-muted-foreground">
              Monitor and respond to security threats in real-time
            </p>
          </div>
          
          <button
            onClick={() => {
              fetchThreats();
              fetchStats();
            }}
            className="btn btn-primary"
            disabled={isLoading}
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="section">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-blue-500/30">
              <div className="flex items-center gap-3 mb-2">
                <Shield className="h-5 w-5 text-blue-500" />
                <div className="text-sm text-muted-foreground">Total Threats</div>
              </div>
              <div className="text-2xl font-bold">
                {stats.total_threats}
              </div>
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-red-500/30">
              <div className="flex items-center gap-3 mb-2">
                <AlertTriangle className="h-5 w-5 text-red-500" />
                <div className="text-sm text-muted-foreground">Critical</div>
              </div>
              <div className="text-2xl font-bold text-red-500">
                {stats.severity_breakdown.critical || 0}
              </div>
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-yellow-500/30">
              <div className="flex items-center gap-3 mb-2">
                <TrendingUp className="h-5 w-5 text-yellow-500" />
                <div className="text-sm text-muted-foreground">Active</div>
              </div>
              <div className="text-2xl font-bold text-yellow-500">
                {stats.status_breakdown.active || 0}
              </div>
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-green-500/30">
              <div className="flex items-center gap-3 mb-2">
                <Shield className="h-5 w-5 text-green-500" />
                <div className="text-sm text-muted-foreground">Blocked</div>
              </div>
              <div className="text-2xl font-bold text-green-500">
                {stats.status_breakdown.blocked || 0}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters & Table */}
      <div className="section">
        <div className="card-premium p-6">
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-4 mb-6">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Filters:</span>
            </div>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground ml-auto transition-all duration-300 hover:border-purple-400 hover:bg-purple-500/5 focus:outline-none focus:ring-2 focus:ring-purple-500 cursor-pointer relative z-50"
              style={{ 
                pointerEvents: 'auto',
                colorScheme: 'dark'
              }}
            >
              <option value="all" className="bg-[#0a0e27] text-white">All Severities</option>
              <option value="critical" className="bg-[#0a0e27] text-white">Critical</option>
              <option value="high" className="bg-[#0a0e27] text-white">High</option>
              <option value="medium" className="bg-[#0a0e27] text-white">Medium</option>
              <option value="low" className="bg-[#0a0e27] text-white">Low</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all duration-300 hover:border-cyan-400 hover:bg-cyan-500/5 focus:outline-none focus:ring-2 focus:ring-cyan-500 cursor-pointer relative z-50"
              style={{ 
                pointerEvents: 'auto',
                colorScheme: 'dark'
              }}
            >
              <option value="all" className="bg-[#0a0e27] text-white">All Statuses</option>
              <option value="active" className="bg-[#0a0e27] text-white">Active</option>
              <option value="blocked" className="bg-[#0a0e27] text-white">Blocked</option>
              <option value="dismissed" className="bg-[#0a0e27] text-white">Dismissed</option>
            </select>

            <div className="ml-auto text-sm text-muted-foreground">
              {threats?.length || 0} threats
            </div>
          </div>

          {/* Batch Actions */}
          {selectedThreats.size > 0 && (
            <div className="mb-4 p-4 bg-gradient-to-r from-purple-500/10 to-pink-500/10 border-2 border-purple-500/30 rounded-lg animate-in fade-in slide-in-from-top-2 duration-300">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex items-center justify-center w-8 h-8 rounded-full bg-purple-500/20">
                    <span className="text-sm font-bold text-purple-400">{selectedThreats.size}</span>
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-foreground">
                      {selectedThreats.size} threat{selectedThreats.size > 1 ? 's' : ''} selected
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Choose an action to apply to selected threats
                    </div>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={batchBlockThreats}
                    className="px-4 py-2 rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30 border border-red-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-red-500/50 flex items-center gap-2 relative z-50"
                    style={{ pointerEvents: 'auto' }}
                  >
                    <Ban className="h-4 w-4" />
                    Block All
                  </button>
                  <button
                    onClick={batchDismissThreats}
                    className="px-4 py-2 rounded-lg bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30 border border-yellow-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-yellow-500/50 flex items-center gap-2 relative z-50"
                    style={{ pointerEvents: 'auto' }}
                  >
                    <X className="h-4 w-4" />
                    Dismiss All
                  </button>
                  <button
                    onClick={batchDeleteThreats}
                    className="px-4 py-2 rounded-lg bg-gray-500/20 text-gray-400 hover:bg-gray-500/30 border border-gray-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-gray-500/50 flex items-center gap-2 relative z-50"
                    style={{ pointerEvents: 'auto' }}
                  >
                    <X className="h-4 w-4" />
                    Delete All
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Loading / Error */}
          {isLoading && (
            <div className="text-center py-12">
              <RefreshCw className="h-8 w-8 animate-spin mx-auto text-primary" />
              <p className="mt-4 text-muted-foreground">Loading threats...</p>
            </div>
          )}

          {error && (
            <div className="text-center py-12">
              <AlertTriangle className="h-8 w-8 mx-auto text-red-500" />
              <p className="mt-4 text-red-500">{error}</p>
            </div>
          )}

          {/* Table */}
          {!isLoading && !error && (
            <div className="overflow-x-auto">
              <table className="table w-full table-fixed">
                <colgroup>
                  <col style={{ width: '3%' }} /> {/* Checkbox */}
                  <col style={{ width: '6%' }} /> {/* Time */}
                  <col style={{ width: '10%' }} /> {/* Source IP */}
                  <col style={{ width: '9%' }} /> {/* Type */}
                  <col style={{ width: '25%' }} /> {/* Description - WIDER */}
                  <col style={{ width: '8%' }} /> {/* Severity */}
                  <col style={{ width: '11%' }} /> {/* Confidence */}
                  <col style={{ width: '10%' }} /> {/* IOC Match */}
                  <col style={{ width: '8%' }} /> {/* Status */}
                  <col style={{ width: '10%' }} /> {/* Actions */}
                </colgroup>
                <thead>
                  <tr>
                    <th className="px-2">
                      <div className="flex items-center justify-center">
                        <input
                          type="checkbox"
                          checked={isSelectAll}
                          onChange={toggleSelectAll}
                          className="w-5 h-5 rounded border-gray-600 bg-gray-700 text-primary focus:ring-primary focus:ring-offset-gray-900 cursor-pointer relative z-[60] transition-all duration-300 hover:scale-110"
                          style={{ pointerEvents: 'auto' }}
                        />
                      </div>
                    </th>
                    <th className="px-2">Time</th>
                    <th className="px-2">Source IP</th>
                    <th className="px-2">Type</th>
                    <th className="px-3">Description</th>
                    <th className="px-2">Severity</th>
                    <th className="px-2">Confidence</th>
                    <th className="px-2">IOC Match</th>
                    <th className="px-2">Status</th>
                    <th className="px-2">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {threats?.length === 0 ? (
                    <tr>
                      <td colSpan={10} className="text-center py-8 text-muted-foreground">
                        No threats found
                      </td>
                    </tr>
                  ) : (
                    threats?.map((threat) => (
                      <tr 
                        key={threat.id}
                        className={`
                          group
                          transition-all duration-300
                          ${getRowHoverGradient(threat.severity)}
                          hover:shadow-lg
                          ${threat.severity === 'critical' ? 'hover:shadow-red-500/20' : ''}
                          ${threat.severity === 'high' ? 'hover:shadow-orange-500/20' : ''}
                          ${threat.severity === 'medium' ? 'hover:shadow-yellow-500/20' : ''}
                          ${threat.severity === 'low' ? 'hover:shadow-blue-500/20' : ''}
                        `}
                      >
                        {/* Checkbox */}
                        <td className="px-2" onClick={(e) => e.stopPropagation()}>
                          <div className="flex items-center justify-center relative z-[60]">
                            <input
                              type="checkbox"
                              checked={selectedThreats.has(threat.id)}
                              onChange={() => toggleThreatSelection(threat.id)}
                              onClick={(e) => e.stopPropagation()}
                              className="w-5 h-5 rounded border-gray-600 bg-gray-700 text-primary focus:ring-primary focus:ring-offset-gray-900 cursor-pointer transition-all duration-300 hover:scale-110"
                              style={{ pointerEvents: 'auto' }}
                            />
                          </div>
                        </td>
                        
                        {/* Time */}
                        <td className="px-2 font-mono text-xs transition-colors duration-300 group-hover:text-blue-400">
                          {formatTime(threat.timestamp)}
                        </td>
                        
                        {/* Source IP - 🆕 Enhanced with copy functionality */}
                        <td className="px-2 font-mono text-xs">
                          <div className="flex items-center gap-1">
                            <span className="text-blue-400 transition-all duration-300 group-hover:text-blue-300 group-hover:drop-shadow-[0_0_8px_rgba(59,130,246,0.5)] truncate">
                              {threat.source_ip}
                            </span>
                            <button
                              onClick={() => copyIpToClipboard(threat.source_ip)}
                              className="opacity-0 group-hover:opacity-100 transition-all duration-300 hover:scale-110 text-gray-400 hover:text-blue-400 relative z-50 flex-shrink-0"
                              style={{ pointerEvents: 'auto' }}
                              title="Copy IP"
                            >
                              {copiedIp === threat.source_ip ? (
                                <CheckCircle2 className="h-3 w-3 text-green-400" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                            </button>
                          </div>
                        </td>
                        
                        {/* Type */}
                        <td className="px-2 font-semibold text-sm transition-colors duration-300 group-hover:text-purple-400 truncate">
                          {threat.threat_type}
                        </td>
                        
                        {/* Description - FIXED with proper truncation */}
                        <td className="px-3 text-sm" title={threat.description}>
                          <div className="truncate transition-colors duration-300 group-hover:text-foreground">
                            {threat.description}
                          </div>
                        </td>
                        
                        {/* Severity - 🆕 Enhanced badge with pulse */}
                        <td className="px-2">
                          <span className={`
                            ${getSeverityBadgeClass(threat.severity)}
                            transition-all duration-300
                            group-hover:scale-110
                            ${threat.severity === 'critical' ? 'group-hover:shadow-lg group-hover:shadow-red-500/50' : ''}
                            ${threat.severity === 'high' ? 'group-hover:shadow-lg group-hover:shadow-orange-500/50' : ''}
                            relative inline-block whitespace-nowrap
                          `}>
                            {threat.severity === 'critical' && (
                              <span className="absolute -top-1 -right-1 flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                              </span>
                            )}
                            {threat.severity}
                          </span>
                        </td>
                        
                        {/* Confidence Score - 🆕 Enhanced with shimmer */}
                        <td className="px-2">
                          <div className="flex items-center gap-2">
                            <div className="w-14 bg-gray-700 rounded-full h-2 overflow-hidden relative group-hover:shadow-md flex-shrink-0">
                              {/* Shimmer effect */}
                              <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-shimmer" />
                              </div>
                              
                              {/* Fill bar */}
                              <div
                                className={`
                                  h-2 rounded-full transition-all duration-500
                                  ${(threat.confidence_score || 0) >= 80 ? 'bg-green-500 group-hover:shadow-green-500/50' :
                                    (threat.confidence_score || 0) >= 60 ? 'bg-yellow-500 group-hover:shadow-yellow-500/50' :
                                    'bg-red-500 group-hover:shadow-red-500/50'}
                                `}
                                style={{ 
                                  width: `${threat.confidence_score || 0}%`,
                                  animation: 'fillBar 1s ease-out'
                                }}
                              />
                            </div>
                            <span className="text-xs font-mono transition-all duration-300 group-hover:text-foreground group-hover:font-semibold whitespace-nowrap">
                              {(threat.confidence_score || 0).toFixed(1)}%
                            </span>
                          </div>
                        </td>
                        
                        {/* IOC Match - 🆕 Enhanced badge */}
                        <td className="px-2">
                          {threat.correlation && threat.correlation.match_count > 0 ? (
                            <div className="flex flex-col gap-1">
                              <div className="flex items-center gap-1">
                                <span className="px-2 py-0.5 bg-purple-500/20 border border-purple-500/30 rounded text-xs text-purple-400 font-medium transition-all duration-300 group-hover:bg-purple-500/30 group-hover:scale-105 group-hover:shadow-lg group-hover:shadow-purple-500/50 whitespace-nowrap">
                                  🔗 {threat.correlation.match_count} IOC{threat.correlation.match_count > 1 ? 's' : ''}
                                </span>
                              </div>
                              <div className="flex items-center gap-1">
                                <span className="text-xs text-gray-400 transition-colors duration-300 group-hover:text-purple-300 whitespace-nowrap">
                                  {threat.correlation.correlation_score}% conf
                                </span>
                              </div>
                            </div>
                          ) : (
                            <span className="text-xs text-gray-500 transition-colors duration-300 group-hover:text-gray-400 whitespace-nowrap">
                              No match
                            </span>
                          )}
                        </td>
                        
                        {/* Status - 🆕 Enhanced badge */}
                        <td className="px-2">
                          <span className={`
                            ${getStatusBadgeClass(threat.status)}
                            transition-all duration-300
                            group-hover:scale-110
                            ${threat.status === 'active' ? 'group-hover:shadow-lg group-hover:shadow-red-500/50' : ''}
                            ${threat.status === 'blocked' ? 'group-hover:shadow-lg group-hover:shadow-green-500/50' : ''}
                            relative inline-block whitespace-nowrap
                          `}>
                            {threat.status === 'active' && (
                              <span className="absolute -top-1 -right-1 flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-yellow-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-yellow-500"></span>
                              </span>
                            )}
                            {threat.status}
                          </span>
                        </td>
                        
                        {/* Actions - 🆕 Enhanced buttons */}
                        <td className="px-2">
                          <div className="flex gap-1.5">
                            {threat.status === "active" && (
                              <>
                                <button
                                  onClick={() => blockThreat(threat.id)}
                                  className="btn btn-ghost text-red-500 hover:bg-red-500/10 transition-all duration-300 hover:scale-110 hover:shadow-lg hover:shadow-red-500/50 relative z-50 p-1.5"
                                  style={{ pointerEvents: 'auto' }}
                                  title="Block Threat"
                                >
                                  <Ban className="h-4 w-4 transition-transform duration-300 hover:rotate-12" />
                                </button>
                                <button
                                  onClick={() => dismissThreat(threat.id)}
                                  className="btn btn-ghost hover:bg-muted transition-all duration-300 hover:scale-110 hover:shadow-lg hover:shadow-gray-500/50 relative z-50 p-1.5"
                                  style={{ pointerEvents: 'auto' }}
                                  title="Dismiss Threat"
                                >
                                  <X className="h-4 w-4 transition-transform duration-300 hover:rotate-90" />
                                </button>
                              </>
                            )}
                            {threat.status !== "active" && (
                              <span className="text-xs text-muted-foreground transition-colors duration-300 group-hover:text-foreground whitespace-nowrap">
                                {threat.status}
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </main>
    </ProtectedRoute>
  );
}