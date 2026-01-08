"use client";

import { useState, ChangeEvent, useEffect, useCallback } from "react";
import { Shield, Activity, Search, Upload, AlertTriangle, XCircle, ExternalLink } from "lucide-react";
import { detectionApi } from "@/lib/api";
import ProtectedRoute from '@/components/ProtectedRoute';

// Types
type Scan = {
  id: number;
  scan_type: string;
  status: string;
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  items_scanned: number;
  threats_found: number;
  results?: Record<string, any>;
};

type DetectionStatus = {
  engine_status: string;
  last_update: string;
  signatures_count: number;
  scans_today: number;
  threats_blocked: number;
};

type UploadResult = {
  success: boolean;
  scan_id: number;
  file_name: string;
  file_size: number;
  threat_score: number;
  severity: string;
  threats_found: number;
  stats: {
    malicious: number;
    suspicious: number;
    undetected: number;
    harmless: number;
    timeout: number;
    total_engines: number;
  };
  detections: Array<{
    engine: string;
    category: string;
    result: string;
  }>;
  vt_link: string;
  hashes: {
    md5: string;
    sha1: string;
    sha256: string;
  };
};

export default function DetectionPageV2() {
  // State
  const [scans, setScans] = useState<Scan[]>([]);
  const [status, setStatus] = useState<DetectionStatus | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // File upload states
  const [isUploading, setIsUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<UploadResult | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // Fetch detection status
  const fetchStatus = useCallback(async () => {
    try {
      const response = await detectionApi.getStatus();
      if (response.success && response.data) {
        setStatus(response.data);
      }
    } catch (err) {
      console.error("Error fetching status:", err);
    }
  }, []);

  // Fetch scans
  const fetchScans = useCallback(async () => {
    try {
      setIsLoading(true);
      const response = await detectionApi.getScans(10);
      if (response.success && response.data) {
        setScans(response.data);
        setError(null);
      } else {
        setError(response.error || "Failed to fetch scans");
      }
    } catch (err) {
      console.error("Error fetching scans:", err);
      setError("Could not load scans");
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    fetchScans();
    fetchStatus();
  }, [fetchScans, fetchStatus]);

  // File upload handler
  const handleFileChange = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    console.log("File selected:", file.name);
    
    setIsUploading(true);
    setUploadError(null);
    setUploadResult(null);

    try {
      const response = await detectionApi.uploadFile(file);

      if (response.success && response.data) {
        console.log("Upload successful:", response.data);
        setUploadResult(response.data);
        await fetchScans();
        await fetchStatus();
      } else {
        setUploadError(response.error || 'Upload failed');
      }
    } catch (err: any) {
      console.error("Upload error:", err);
      setUploadError(err.message || 'Failed to upload file');
    } finally {
      setIsUploading(false);
      e.target.value = '';
    }
  };

  // Get severity color
  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: 'text-red-500',
      high: 'text-orange-500',
      medium: 'text-yellow-500',
      low: 'text-blue-500',
      clean: 'text-green-500',
      pending: 'text-gray-500'
    };
    return colors[severity] || 'text-gray-500';
  };

  const getSeverityBg = (severity: string) => {
    const colors: Record<string, string> = {
      critical: 'bg-red-500/10 border-red-500/30',
      high: 'bg-orange-500/10 border-orange-500/30',
      medium: 'bg-yellow-500/10 border-yellow-500/30',
      low: 'bg-blue-500/10 border-blue-500/30',
      clean: 'bg-green-500/10 border-green-500/30',
      pending: 'bg-gray-500/10 border-gray-500/30'
    };
    return colors[severity] || 'bg-gray-500/10 border-gray-500/30';
  };

  // Get row hover gradient based on threats
  const getRowHoverGradient = (threatsCount: number) => {
    if (threatsCount > 0) {
      return "hover:bg-gradient-to-r hover:from-red-500/10 hover:via-red-500/5 hover:to-transparent";
    }
    return "hover:bg-gradient-to-r hover:from-green-500/10 hover:via-green-500/5 hover:to-transparent";
  };

  return (
      <ProtectedRoute>
    <main className="pb-12">
      {/* Hero */}
      <div className="page-container page-hero pt-12 md:pt-16">
        <div>
          <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
            Threat Detection v2
          </h1>
          <p className="mt-2 text-muted-foreground">
            Advanced real-time file scanning with VirusTotal integration
          </p>
        </div>
      </div>

      {/* Status Cards */}
      {status && (
        <div className="section">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-green-500/30 group cursor-pointer relative overflow-hidden">
              <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-white/5 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              
              <div className="flex items-center gap-3 mb-2 relative z-10">
                <div className="p-2 bg-green-500/10 rounded-lg transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-green-500/50">
                  <Shield className="h-5 w-5 text-green-500 transition-transform duration-300 group-hover:rotate-12" />
                </div>
                <div className="text-sm text-muted-foreground transition-colors duration-300 group-hover:text-gray-300">Engine Status</div>
              </div>
              <div className="text-2xl font-bold text-green-500 transition-all duration-300 group-hover:scale-110 origin-left">
                {status.engine_status}
              </div>
              
              {status.engine_status === 'online' && (
                <div className="absolute top-4 right-4 flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
                </div>
              )}
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-blue-500/30 group cursor-pointer relative overflow-hidden">
              <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-white/5 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              
              <div className="flex items-center gap-3 mb-2 relative z-10">
                <div className="p-2 bg-blue-500/10 rounded-lg transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-blue-500/50">
                  <Activity className="h-5 w-5 text-blue-500 transition-transform duration-300 group-hover:rotate-12" />
                </div>
                <div className="text-sm text-muted-foreground transition-colors duration-300 group-hover:text-gray-300">Signatures</div>
              </div>
              <div className="text-2xl font-bold text-blue-500 transition-all duration-300 group-hover:scale-110 origin-left">
                {status.signatures_count.toLocaleString()}
              </div>
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/30 group cursor-pointer relative overflow-hidden">
              <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-white/5 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              
              <div className="flex items-center gap-3 mb-2 relative z-10">
                <div className="p-2 bg-purple-500/10 rounded-lg transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-purple-500/50">
                  <Search className="h-5 w-5 text-purple-500 transition-transform duration-300 group-hover:rotate-12" />
                </div>
                <div className="text-sm text-muted-foreground transition-colors duration-300 group-hover:text-gray-300">Scans Today</div>
              </div>
              <div className="text-2xl font-bold text-purple-500 transition-all duration-300 group-hover:scale-110 origin-left">
                {status.scans_today}
              </div>
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-red-500/30 group cursor-pointer relative overflow-hidden">
              <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-white/5 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              
              <div className="flex items-center gap-3 mb-2 relative z-10">
                <div className="p-2 bg-red-500/10 rounded-lg transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-red-500/50">
                  <AlertTriangle className="h-5 w-5 text-red-500 transition-transform duration-300 group-hover:rotate-12" />
                </div>
                <div className="text-sm text-muted-foreground transition-colors duration-300 group-hover:text-gray-300">Threats Blocked</div>
              </div>
              <div className="text-2xl font-bold text-red-500 transition-all duration-300 group-hover:scale-110 origin-left">
                {status.threats_blocked}
              </div>
              
              {status.threats_blocked > 0 && (
                <div className="absolute top-4 right-4 flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* File Upload Section */}
      <div className="section">
        <div className="bg-card border border-border rounded-lg p-8 transition-all duration-300 hover:border-purple-500/30 group relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-purple-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
          
          <h2 className="text-xl font-semibold mb-6 flex items-center gap-2 relative z-10">
            <Upload className="h-5 w-5 text-purple-500 transition-transform duration-300 group-hover:scale-110" />
            Upload File for Scanning
          </h2>

          <div className="text-center relative z-10">
            {isUploading ? (
              <div className="flex flex-col items-center gap-4 py-8">
                <Activity className="h-12 w-12 text-purple-500 animate-spin" />
                <p className="text-lg font-medium">Scanning file...</p>
                <p className="text-sm text-muted-foreground">Please wait while we analyze your file</p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-gradient-to-br from-purple-500/20 to-cyan-500/20 mb-4 animate-float">
                  <Upload className="h-10 w-10 text-purple-500" />
                </div>
                <p className="text-lg font-medium mb-2">
                  Select a file to scan
                </p>
                <p className="text-sm text-muted-foreground mb-6">
                  Maximum file size: 32MB
                </p>
                
                <div className="flex justify-center">
                  <label className="relative cursor-pointer">
                    <input
                      type="file"
                      onChange={handleFileChange}
                      disabled={isUploading}
                      accept="*/*"
                      className="
                        block w-full max-w-xs text-sm text-muted-foreground
                        file:mr-4 file:py-3 file:px-6
                        file:rounded-lg file:border-0
                        file:text-sm file:font-semibold
                        file:bg-purple-500 file:text-white
                        hover:file:bg-purple-600
                        file:transition-all file:duration-300
                        file:cursor-pointer
                        hover:file:scale-105 hover:file:shadow-lg hover:file:shadow-purple-500/50
                        disabled:opacity-50 disabled:cursor-not-allowed
                      "
                    />
                  </label>
                </div>
              </div>
            )}
          </div>

          {uploadError && (
            <div className="mt-6 p-4 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center gap-3 animate-in fade-in slide-in-from-top-2 duration-300">
              <XCircle className="h-5 w-5 text-red-500 flex-shrink-0" />
              <p className="text-red-500">{uploadError}</p>
            </div>
          )}
        </div>
      </div>

      {/* Upload Results */}
      {uploadResult && (
        <div className="section animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
              <Shield className="h-5 w-5 text-cyan-500" />
              Scan Results
            </h2>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Threat Score Gauge */}
              <div className="lg:col-span-1">
                <div className={`p-6 rounded-lg border-2 ${getSeverityBg(uploadResult.severity)} transition-all duration-300 hover:scale-105`}>
                  <div className="text-center">
                    <div className={`text-6xl font-bold mb-2 ${getSeverityColor(uploadResult.severity)}`}>
                      {uploadResult.threat_score}
                    </div>
                    <div className="text-sm text-muted-foreground mb-4">Threat Score</div>
                    <div className={`inline-block px-4 py-2 rounded-full ${getSeverityBg(uploadResult.severity)} font-semibold uppercase text-sm ${getSeverityColor(uploadResult.severity)}`}>
                      {uploadResult.severity}
                    </div>
                  </div>
                </div>

                <div className="mt-4 space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">File:</span>
                    <span className="font-medium">{uploadResult.file_name}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Size:</span>
                    <span className="font-medium">{(uploadResult.file_size / 1024).toFixed(2)} KB</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Threats:</span>
                    <span className={`font-bold ${uploadResult.threats_found > 0 ? 'text-red-500' : 'text-green-500'}`}>
                      {uploadResult.threats_found}
                    </span>
                  </div>
                </div>
              </div>

              {/* Detection Stats */}
              <div className="lg:col-span-2 space-y-4">
                <div>
                  <h3 className="text-lg font-semibold mb-3">Detection Statistics</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-red-500/30">
                      <div className="text-2xl font-bold text-red-500">{uploadResult.stats.malicious}</div>
                      <div className="text-sm text-muted-foreground">Malicious</div>
                    </div>
                    <div className="p-4 rounded-lg bg-orange-500/10 border border-orange-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-orange-500/30">
                      <div className="text-2xl font-bold text-orange-500">{uploadResult.stats.suspicious}</div>
                      <div className="text-sm text-muted-foreground">Suspicious</div>
                    </div>
                    <div className="p-4 rounded-lg bg-green-500/10 border border-green-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-green-500/30">
                      <div className="text-2xl font-bold text-green-500">{uploadResult.stats.harmless}</div>
                      <div className="text-sm text-muted-foreground">Harmless</div>
                    </div>
                    <div className="p-4 rounded-lg bg-gray-500/10 border border-gray-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-gray-500/30">
                      <div className="text-2xl font-bold text-gray-400">{uploadResult.stats.undetected}</div>
                      <div className="text-sm text-muted-foreground">Undetected</div>
                    </div>
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-muted-foreground">Engines Scanned</span>
                    <span className="font-bold">{uploadResult.stats.total_engines}</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-gradient-to-r from-purple-500 to-cyan-500 transition-all duration-500 animate-fillBar"
                      style={{ width: '100%' }}
                    />
                  </div>
                </div>

                {/* File Hashes */}
                <div>
                  <h3 className="text-lg font-semibold mb-3">File Hashes</h3>
                  <div className="space-y-2 text-sm font-mono">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">MD5:</span>
                      <span className="text-cyan-400">{uploadResult.hashes.md5}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">SHA1:</span>
                      <span className="text-cyan-400">{uploadResult.hashes.sha1}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">SHA256:</span>
                      <span className="text-cyan-400 text-xs break-all">{uploadResult.hashes.sha256}</span>
                    </div>
                  </div>
                </div>

                {/* VirusTotal Link */}
                <a
                  href={uploadResult.vt_link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-center gap-2 px-4 py-3 rounded-lg bg-purple-500/10 text-purple-500 hover:bg-purple-500/20 border-2 border-purple-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/50"
                >
                  <ExternalLink className="h-4 w-4" />
                  View Full Report on VirusTotal
                </a>
              </div>
            </div>

            {/* Detections List */}
            {uploadResult.detections.length > 0 && (
              <div className="mt-6">
                <h3 className="text-lg font-semibold mb-3 text-red-500">⚠️ Detections Found</h3>
                <div className="space-y-2">
                  {uploadResult.detections.map((detection, index) => (
                    <div key={index} className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-between transition-all duration-300 hover:bg-red-500/20 hover:scale-[1.02]">
                      <div>
                        <div className="font-medium">{detection.engine}</div>
                        <div className="text-sm text-muted-foreground">{detection.result}</div>
                      </div>
                      <span className="px-3 py-1 rounded-full bg-red-500 text-white text-xs font-semibold uppercase">
                        {detection.category}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Recent Scans */}
      <div className="section">
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-xl font-semibold mb-6">Recent Scans</h2>

          {isLoading ? (
            <div className="text-center py-12">
              <Activity className="h-8 w-8 animate-spin mx-auto text-purple-500" />
              <p className="mt-4 text-muted-foreground">Loading scans...</p>
            </div>
          ) : error ? (
            <div className="text-center py-12">
              <AlertTriangle className="h-8 w-8 mx-auto text-red-500" />
              <p className="mt-4 text-red-500">{error}</p>
            </div>
          ) : scans.length === 0 ? (
            <div className="text-center py-12">
              <Search className="h-8 w-8 mx-auto text-gray-500" />
              <p className="mt-4 text-muted-foreground">No scans yet. Upload a file to start!</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left py-3 px-4 text-sm font-semibold">ID</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold">Type</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold">Status</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold">Started</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold">Duration</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold">Items</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold">Threats</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan) => (
                    <tr 
                      key={scan.id} 
                      className={`
                        border-b border-border transition-all duration-300 group
                        ${getRowHoverGradient(scan.threats_found)}
                        hover:shadow-lg
                        ${scan.threats_found > 0 ? 'hover:shadow-red-500/20' : 'hover:shadow-green-500/20'}
                      `}
                    >
                      <td className="py-3 px-4 transition-colors duration-300 group-hover:text-foreground">#{scan.id}</td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-1 rounded-full bg-blue-500/10 text-blue-500 text-xs font-semibold transition-all duration-300 group-hover:scale-105 group-hover:shadow-lg group-hover:shadow-blue-500/50">
                          {scan.scan_type}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`
                          px-2 py-1 rounded-full text-xs font-semibold transition-all duration-300 group-hover:scale-105 relative
                          ${scan.status === 'completed' ? 'bg-green-500/10 text-green-500 group-hover:shadow-lg group-hover:shadow-green-500/50' : 
                            scan.status === 'running' ? 'bg-yellow-500/10 text-yellow-500 group-hover:shadow-lg group-hover:shadow-yellow-500/50' : 
                            'bg-red-500/10 text-red-500 group-hover:shadow-lg group-hover:shadow-red-500/50'}
                        `}>
                          {scan.status === 'completed' && (
                            <span className="absolute -top-1 -right-1 flex h-2 w-2">
                              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                            </span>
                          )}
                          {scan.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-sm transition-colors duration-300 group-hover:text-foreground">
                        {new Date(scan.started_at).toLocaleString('en-US', {
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        })}
                      </td>
                      <td className="py-3 px-4 transition-colors duration-300 group-hover:text-foreground">
                        {scan.duration_seconds ? `${scan.duration_seconds.toFixed(2)}s` : '—'}
                      </td>
                      <td className="py-3 px-4 transition-colors duration-300 group-hover:text-foreground">{scan.items_scanned}</td>
                      <td className="py-3 px-4">
                        <span className={`font-bold transition-all duration-300 group-hover:scale-110 inline-block ${scan.threats_found > 0 ? 'text-red-500' : 'text-green-500'}`}>
                          {scan.threats_found}
                        </span>
                      </td>
                    </tr>
                  ))}
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