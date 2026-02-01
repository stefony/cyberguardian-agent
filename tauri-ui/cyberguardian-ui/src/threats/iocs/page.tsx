"use client";
import { httpFetch } from "@/lib/api";
import { useState, useEffect } from "react";
import { Shield, Database, AlertTriangle, TrendingUp } from "lucide-react";
import IOCTable from "@/components/threats/IOCTable";
import IOCFilters from "@/components/threats/IOCFilters";
import IOCStats from "@/components/threats/IOCStats";
import ProtectedRoute from '@/components/ProtectedRoute';

// Helper to make authenticated requests
const fetchWithAuth = async (endpoint: string) => {
  const token = typeof window !== "undefined" ? localStorage.getItem("access_token") : null;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await httpFetch(endpoint, { headers });
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
  
  // Pagination
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [totalIOCs, setTotalIOCs] = useState<number>(0);
  const ITEMS_PER_PAGE = 20;

  useEffect(() => {
    fetchIOCs();
    fetchStats();
  }, [selectedType, selectedSeverity, selectedSource, currentPage]);

  const fetchIOCs = async () => {
    setLoading(true);
    try {
      const offset = (currentPage - 1) * ITEMS_PER_PAGE;
      let url = `/api/threat-intel/iocs?limit=${ITEMS_PER_PAGE}&offset=${offset}`;
      
      if (selectedType !== "all") url += `&ioc_type=${selectedType}`;
      if (selectedSeverity !== "all") url += `&severity=${selectedSeverity}`;
      if (selectedSource !== "all") url += `&source=${selectedSource}`;

      const data = await fetchWithAuth(url);
      
      if (data.success && data.iocs) {
        setIocs(data.iocs);
        // Update pagination info
        const total = data.total || stats?.total_iocs || 0;
        setTotalIOCs(total);
        setTotalPages(Math.ceil(total / ITEMS_PER_PAGE));
      } else {
        console.error('No IOCs returned from API');
        setIocs([]);
      }
    } catch (error) {
      console.error("Failed to fetch IOCs:", error);
      setIocs([]);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const data = await fetchWithAuth('/api/threat-intel/statistics');

      if (data.success && data.statistics) {
        setStats(data.statistics);
      } else {
        console.error('No stats returned from API');
        setStats(null);
      }
    } catch (error) {
      console.error("Failed to fetch stats:", error);
      setStats(null);
    }
  };

  const handleRefresh = () => {
    fetchIOCs();
    fetchStats();
  };

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
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
          stats={stats}
        />

        {/* IOC Table */}
        <IOCTable iocs={iocs} loading={loading} />

        {/* Pagination */}
        {!loading && iocs.length > 0 && (
          <div className="flex items-center justify-between bg-slate-800/50 rounded-lg p-4">
            <div className="text-sm text-gray-400">
              Showing {((currentPage - 1) * ITEMS_PER_PAGE) + 1} - {Math.min(currentPage * ITEMS_PER_PAGE, totalIOCs)} of {totalIOCs} IOCs
            </div>
            
            <div className="flex items-center gap-2">
              <button
                onClick={() => handlePageChange(currentPage - 1)}
                disabled={currentPage === 1}
                className="px-3 py-1 rounded bg-slate-700 hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm"
              >
                ← Previous
              </button>
              
              <div className="flex items-center gap-1">
                {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
                  let pageNum;
                  if (totalPages <= 5) {
                    pageNum = i + 1;
                  } else if (currentPage <= 3) {
                    pageNum = i + 1;
                  } else if (currentPage >= totalPages - 2) {
                    pageNum = totalPages - 4 + i;
                  } else {
                    pageNum = currentPage - 2 + i;
                  }
                  
                  return (
                    <button
                      key={pageNum}
                      onClick={() => handlePageChange(pageNum)}
                      className={`px-3 py-1 rounded text-sm ${
                        currentPage === pageNum
                          ? 'bg-cyan-500 text-white'
                          : 'bg-slate-700 hover:bg-slate-600 text-white'
                      }`}
                    >
                      {pageNum}
                    </button>
                  );
                })}
              </div>
              
              <button
                onClick={() => handlePageChange(currentPage + 1)}
                disabled={currentPage === totalPages}
                className="px-3 py-1 rounded bg-slate-700 hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm"
              >
                Next →
              </button>
            </div>
          </div>
        )}
      </div>
    </ProtectedRoute>
  );
}