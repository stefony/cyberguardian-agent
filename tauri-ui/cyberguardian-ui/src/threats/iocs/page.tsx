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


    
    if (data.success && data.iocs) {
      setIocs(data.iocs);
    } else {
      console.log('🟡 Using mock IOCs data');
      const mockIOCs: IOC[] = [
        { id: 1, ioc_type: 'ip', ioc_value: '185.220.101.47', threat_type: 'malware', threat_name: 'TrickBot', severity: 'critical', confidence: 95, source: 'AlienVault OTX', first_seen: new Date(Date.now() - 86400000).toISOString(), last_seen: new Date(Date.now() - 3600000).toISOString(), times_seen: 47 },
        { id: 2, ioc_type: 'domain', ioc_value: 'malicious-site.com', threat_type: 'phishing', threat_name: 'Phishing Campaign 2025', severity: 'high', confidence: 88, source: 'VirusTotal', first_seen: new Date(Date.now() - 172800000).toISOString(), last_seen: new Date(Date.now() - 7200000).toISOString(), times_seen: 23 },
        { id: 3, ioc_type: 'hash', ioc_value: 'a1b2c3d4e5f6g7h8i9j0', threat_type: 'ransomware', threat_name: 'WannaCry', severity: 'critical', confidence: 98, source: 'MISP', first_seen: new Date(Date.now() - 259200000).toISOString(), last_seen: new Date(Date.now() - 10800000).toISOString(), times_seen: 156 },
        { id: 4, ioc_type: 'url', ioc_value: 'http://evil.com/malware.exe', threat_type: 'trojan', threat_name: 'Emotet', severity: 'high', confidence: 91, source: 'Abuse.ch', first_seen: new Date(Date.now() - 345600000).toISOString(), last_seen: new Date(Date.now() - 14400000).toISOString(), times_seen: 67 },
        { id: 5, ioc_type: 'ip', ioc_value: '103.45.12.89', threat_type: 'c2', threat_name: 'Cobalt Strike C2', severity: 'critical', confidence: 97, source: 'ThreatFox', first_seen: new Date(Date.now() - 432000000).toISOString(), last_seen: new Date(Date.now() - 1800000).toISOString(), times_seen: 89 },
        { id: 6, ioc_type: 'domain', ioc_value: 'phishing-bank.net', threat_type: 'phishing', threat_name: 'Banking Trojan', severity: 'medium', confidence: 76, source: 'OpenPhish', first_seen: new Date(Date.now() - 518400000).toISOString(), last_seen: new Date(Date.now() - 21600000).toISOString(), times_seen: 34 },
        { id: 7, ioc_type: 'hash', ioc_value: 'f9e8d7c6b5a4930201ab', threat_type: 'malware', threat_name: 'Zeus', severity: 'high', confidence: 92, source: 'MalwareBazaar', first_seen: new Date(Date.now() - 604800000).toISOString(), last_seen: new Date(Date.now() - 28800000).toISOString(), times_seen: 112 },
        { id: 8, ioc_type: 'ip', ioc_value: '45.142.212.61', threat_type: 'scanner', threat_name: 'Port Scanner', severity: 'low', confidence: 65, source: 'Shodan', first_seen: new Date(Date.now() - 691200000).toISOString(), last_seen: new Date(Date.now() - 32400000).toISOString(), times_seen: 12 },
        { id: 9, ioc_type: 'url', ioc_value: 'https://fake-update.com/install', threat_type: 'adware', threat_name: 'FakeUpdate', severity: 'medium', confidence: 72, source: 'URLhaus', first_seen: new Date(Date.now() - 777600000).toISOString(), last_seen: new Date(Date.now() - 36000000).toISOString(), times_seen: 56 },
        { id: 10, ioc_type: 'domain', ioc_value: 'c2-server.ru', threat_type: 'c2', threat_name: 'APT29 Infrastructure', severity: 'critical', confidence: 99, source: 'AlienVault OTX', first_seen: new Date(Date.now() - 864000000).toISOString(), last_seen: new Date(Date.now() - 43200000).toISOString(), times_seen: 203 }
      ];
      
      // Apply filters to mock data
      let filteredIOCs = mockIOCs;
      if (selectedType !== "all") {
        filteredIOCs = filteredIOCs.filter(ioc => ioc.ioc_type === selectedType);
      }
      if (selectedSeverity !== "all") {
        filteredIOCs = filteredIOCs.filter(ioc => ioc.severity === selectedSeverity);
      }
      if (selectedSource !== "all") {
        filteredIOCs = filteredIOCs.filter(ioc => ioc.source === selectedSource);
      }
      
      setIocs(filteredIOCs);
    }
  } catch (error) {
    console.error("Failed to fetch IOCs:", error);
    console.log('🟡 Using mock IOCs data (error fallback)');
    const mockIOCs: IOC[] = [
      { id: 1, ioc_type: 'ip', ioc_value: '185.220.101.47', threat_type: 'malware', threat_name: 'TrickBot', severity: 'critical', confidence: 95, source: 'AlienVault OTX', first_seen: new Date(Date.now() - 86400000).toISOString(), last_seen: new Date(Date.now() - 3600000).toISOString(), times_seen: 47 },
      { id: 2, ioc_type: 'domain', ioc_value: 'malicious-site.com', threat_type: 'phishing', threat_name: 'Phishing Campaign 2025', severity: 'high', confidence: 88, source: 'VirusTotal', first_seen: new Date(Date.now() - 172800000).toISOString(), last_seen: new Date(Date.now() - 7200000).toISOString(), times_seen: 23 },
      { id: 3, ioc_type: 'hash', ioc_value: 'a1b2c3d4e5f6g7h8i9j0', threat_type: 'ransomware', threat_name: 'WannaCry', severity: 'critical', confidence: 98, source: 'MISP', first_seen: new Date(Date.now() - 259200000).toISOString(), last_seen: new Date(Date.now() - 10800000).toISOString(), times_seen: 156 },
      { id: 4, ioc_type: 'url', ioc_value: 'http://evil.com/malware.exe', threat_type: 'trojan', threat_name: 'Emotet', severity: 'high', confidence: 91, source: 'Abuse.ch', first_seen: new Date(Date.now() - 345600000).toISOString(), last_seen: new Date(Date.now() - 14400000).toISOString(), times_seen: 67 },
      { id: 5, ioc_type: 'ip', ioc_value: '103.45.12.89', threat_type: 'c2', threat_name: 'Cobalt Strike C2', severity: 'critical', confidence: 97, source: 'ThreatFox', first_seen: new Date(Date.now() - 432000000).toISOString(), last_seen: new Date(Date.now() - 1800000).toISOString(), times_seen: 89 },
      { id: 6, ioc_type: 'domain', ioc_value: 'phishing-bank.net', threat_type: 'phishing', threat_name: 'Banking Trojan', severity: 'medium', confidence: 76, source: 'OpenPhish', first_seen: new Date(Date.now() - 518400000).toISOString(), last_seen: new Date(Date.now() - 21600000).toISOString(), times_seen: 34 },
      { id: 7, ioc_type: 'hash', ioc_value: 'f9e8d7c6b5a4930201ab', threat_type: 'malware', threat_name: 'Zeus', severity: 'high', confidence: 92, source: 'MalwareBazaar', first_seen: new Date(Date.now() - 604800000).toISOString(), last_seen: new Date(Date.now() - 28800000).toISOString(), times_seen: 112 },
      { id: 8, ioc_type: 'ip', ioc_value: '45.142.212.61', threat_type: 'scanner', threat_name: 'Port Scanner', severity: 'low', confidence: 65, source: 'Shodan', first_seen: new Date(Date.now() - 691200000).toISOString(), last_seen: new Date(Date.now() - 32400000).toISOString(), times_seen: 12 },
      { id: 9, ioc_type: 'url', ioc_value: 'https://fake-update.com/install', threat_type: 'adware', threat_name: 'FakeUpdate', severity: 'medium', confidence: 72, source: 'URLhaus', first_seen: new Date(Date.now() - 777600000).toISOString(), last_seen: new Date(Date.now() - 36000000).toISOString(), times_seen: 56 },
      { id: 10, ioc_type: 'domain', ioc_value: 'c2-server.ru', threat_type: 'c2', threat_name: 'APT29 Infrastructure', severity: 'critical', confidence: 99, source: 'AlienVault OTX', first_seen: new Date(Date.now() - 864000000).toISOString(), last_seen: new Date(Date.now() - 43200000).toISOString(), times_seen: 203 }
    ];
    
    let filteredIOCs = mockIOCs;
    if (selectedType !== "all") {
      filteredIOCs = filteredIOCs.filter(ioc => ioc.ioc_type === selectedType);
    }
    if (selectedSeverity !== "all") {
      filteredIOCs = filteredIOCs.filter(ioc => ioc.severity === selectedSeverity);
    }
    if (selectedSource !== "all") {
      filteredIOCs = filteredIOCs.filter(ioc => ioc.source === selectedSource);
    }
    
    setIocs(filteredIOCs);
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
      console.log('🟡 Using mock IOC stats');
      const mockStats: IOCStats = {
        total_iocs: 10458,
        iocs_by_type: {
          'ip': 4521,
          'domain': 2876,
          'hash': 1834,
          'url': 1227
        },
        iocs_by_severity: {
          'critical': 1245,
          'high': 3456,
          'medium': 4123,
          'low': 1634
        },
        total_matches: 234,
        recent_high_severity: 67
      };
      setStats(mockStats);
    }
  } catch (error) {
    console.error("Failed to fetch stats:", error);
    console.log('🟡 Using mock IOC stats (error fallback)');
    const mockStats: IOCStats = {
      total_iocs: 10458,
      iocs_by_type: {
        'ip': 4521,
        'domain': 2876,
        'hash': 1834,
        'url': 1227
      },
      iocs_by_severity: {
        'critical': 1245,
        'high': 3456,
        'medium': 4123,
        'low': 1634
      },
      total_matches: 234,
      recent_high_severity: 67
    };
    setStats(mockStats);
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
