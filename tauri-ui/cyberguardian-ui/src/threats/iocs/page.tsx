"use client";

import { useState, useEffect } from "react";
import { Shield, Database, AlertTriangle, TrendingUp } from "lucide-react";
import IOCTable from "@/components/threats/IOCTable";
import IOCFilters from "@/components/threats/IOCFilters";
import IOCStats from "@/components/threats/IOCStats";
import ProtectedRoute from '@/components/ProtectedRoute';

// API configuration
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// Helper to make authenticated requests
const fetchWithAuth = async (endpoint: string) => {
  const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  const response = await fetch(`${API_BASE_URL}${endpoint}`, { headers });
  return response.json();
};

interface IOC {
  id: number;
  ioc_type: string;
  ioc_value: string;
  threat_type: string;
  threat_name: string;
  severity: string;
  confidence: number;
  source: string;
  first_seen: string;
  last_seen: string;
  times_seen: number;
}

interface IOCStats {
  total_iocs: number;
  iocs_by_type: Record<string, number>;
  iocs_by_severity: Record<string, number>;
  total_matches: number;
  recent_high_severity: number;
}

export default function IOCsPage() {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [stats, setStats] = useState<IOCStats | null>(null);
  const [loading, setLoading] = useState(true);
  
  // Filters
  const [selectedType, setSelectedType] = useState<string>("all");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [selectedSource, setSelectedSource] = useState<string>("all");

  useEffect(() => {
    fetchIOCs();
    fetchStats();
  }, [selectedType, selectedSeverity, selectedSource]);

  const fetchIOCs = async () => {
    setLoading(true);
    try {
      let url = `/api/threat-intel/iocs?limit=100`;
      
      if (selectedType !== "all") url += `&ioc_type=${selectedType}`;
      if (selectedSeverity !== "all") url += `&severity=${selectedSeverity}`;
      if (selectedSource !== "all") url += `&source=${selectedSource}`;

      const data = await fetchWithAuth(url);
      
      if (data.success) {
        setIocs(data.iocs || []);
      }
    } catch (error) {
      console.error("Failed to fetch IOCs:", error);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const data = await fetchWithAuth('/api/threat-intel/statistics');
      
      if (data.success) {
        setStats(data.statistics);
      }
    } catch (error) {
      console.error("Failed to fetch stats:", error);
    }
  };

  const handleRefresh = () => {
    fetchIOCs();
    fetchStats();
  };

  return (
    <ProtectedRoute>
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Database className="w-8 h-8 text-cyan-400" />
            Indicators of Compromise
          </h1>
          <p className="text-gray-400 mt-1">
            Threat intelligence indicators from multiple sources
          </p>
        </div>
        
        <button
          onClick={handleRefresh}
          className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg 
                     transition-all duration-200 flex items-center gap-2"
        >
          <TrendingUp className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Statistics Cards */}
      <IOCStats stats={stats} loading={loading} />

      {/* Filters */}
      <IOCFilters
        selectedType={selectedType}
        selectedSeverity={selectedSeverity}
        selectedSource={selectedSource}
        onTypeChange={setSelectedType}
        onSeverityChange={setSelectedSeverity}
        onSourceChange={setSelectedSource}
      />

      {/* IOC Table */}
      <IOCTable iocs={iocs} loading={loading} />
    </div>
    </ProtectedRoute>
  );
}