"use client";

import { useState } from "react";
import {
  Globe,
  Hash,
  Mail,
  Link as LinkIcon,
  ExternalLink,
  Info,
  Copy,
  Check,
  Sparkles
} from "lucide-react";

interface IOC {
  id: number;
  ioc_type: string;
  ioc_value: string;
  threat_type: string | null;
  threat_name: string | null;
  severity: string;
  confidence: number;
  source: string;
  first_seen: string;
  last_seen: string;
  times_seen: number;
  description?: string;
}

interface IOCTableProps {
  iocs: IOC[];
  loading: boolean;
}

export default function IOCTable({ iocs, loading }: IOCTableProps) {
  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [selectedIOC, setSelectedIOC] = useState<IOC | null>(null);

  const getTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case "ip":
        return <Globe className="w-4 h-4" />;
      case "domain":
        return <Globe className="w-4 h-4" />;
      case "hash":
        return <Hash className="w-4 h-4" />;
      case "url":
        return <LinkIcon className="w-4 h-4" />;
      case "email":
        return <Mail className="w-4 h-4" />;
      default:
        return <Info className="w-4 h-4" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-500/20 text-red-400 border-red-500/30";
      case "high":
        return "bg-orange-500/20 text-orange-400 border-orange-500/30";
      case "medium":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
      case "low":
        return "bg-green-500/20 text-green-400 border-green-500/30";
      default:
        return "bg-gray-500/20 text-gray-400 border-gray-500/30";
    }
  };

  const getRowHoverGradient = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "hover:bg-gradient-to-r hover:from-red-500/10 hover:via-red-500/5 hover:to-transparent";
      case "high":
        return "hover:bg-gradient-to-r hover:from-orange-500/10 hover:via-orange-500/5 hover:to-transparent";
      case "medium":
        return "hover:bg-gradient-to-r hover:from-yellow-500/10 hover:via-yellow-500/5 hover:to-transparent";
      case "low":
        return "hover:bg-gradient-to-r hover:from-green-500/10 hover:via-green-500/5 hover:to-transparent";
      default:
        return "hover:bg-gradient-to-r hover:from-purple-500/10 hover:via-purple-500/5 hover:to-transparent";
    }
  };

  const copyToClipboard = (value: string, id: number) => {
    navigator.clipboard.writeText(value);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  if (loading) {
    return (
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <div className="animate-pulse space-y-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-16 bg-gray-700/50 rounded-lg"></div>
          ))}
        </div>
      </div>
    );
  }

  if (iocs.length === 0) {
    return (
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-12 text-center relative overflow-hidden group">
        {/* Floating particles background */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-1/4 left-1/4 w-32 h-32 bg-cyan-500/5 rounded-full blur-3xl animate-float" />
          <div className="absolute bottom-1/4 right-1/4 w-40 h-40 bg-purple-500/5 rounded-full blur-3xl animate-float-delayed" />
        </div>

        <div className="relative z-10">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-gradient-to-br from-cyan-500/20 to-purple-500/20 mb-6 animate-pulse">
            <Info className="w-10 h-10 text-cyan-400" />
          </div>
          
          <h3 className="text-xl font-bold text-white mb-2 bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
            No IOCs Found
          </h3>
          
          <p className="text-gray-400 mb-6 max-w-md mx-auto">
            No indicators match your current filters. Try adjusting your search criteria or refresh the data.
          </p>

          <div className="flex items-center justify-center gap-3">
            <button 
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-cyan-500/20 border border-cyan-500/30 rounded-lg text-cyan-400
                       transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-cyan-500/50
                       flex items-center gap-2"
            >
              <Sparkles className="w-4 h-4" />
              Refresh Data
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-gray-900/50 border-b border-gray-700">
            <tr>
              <th className="px-6 py-4 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Type
              </th>
              <th className="px-6 py-4 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Indicator Value
              </th>
              <th className="px-6 py-4 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Threat
              </th>
              <th className="px-6 py-4 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Severity
              </th>
              <th className="px-6 py-4 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Confidence
              </th>
              <th className="px-6 py-4 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Source
              </th>
              <th className="px-6 py-4 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                First Seen
              </th>
              <th className="px-6 py-4 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>

          <tbody className="divide-y divide-gray-700">
            {iocs.map((ioc) => (
              <tr
                key={ioc.id}
                className={`
                  group cursor-pointer
                  transition-all duration-300
                  ${getRowHoverGradient(ioc.severity)}
                  hover:shadow-lg
                  ${ioc.severity === 'critical' ? 'hover:shadow-red-500/20' : ''}
                  ${ioc.severity === 'high' ? 'hover:shadow-orange-500/20' : ''}
                  ${ioc.severity === 'medium' ? 'hover:shadow-yellow-500/20' : ''}
                  ${ioc.severity === 'low' ? 'hover:shadow-green-500/20' : ''}
                `}
                onClick={() => setSelectedIOC(ioc)}
              >
                {/* Type */}
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    <div className="p-2 bg-cyan-500/10 rounded-lg text-cyan-400 transition-all duration-300 group-hover:scale-110 group-hover:bg-cyan-500/20 group-hover:shadow-lg group-hover:shadow-cyan-500/50">
                      {getTypeIcon(ioc.ioc_type)}
                    </div>
                    <span className="text-sm font-medium text-white capitalize transition-colors duration-300 group-hover:text-cyan-400">
                      {ioc.ioc_type}
                    </span>
                  </div>
                </td>

                {/* IOC Value */}
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2 max-w-xs">
                    <span className="text-sm text-gray-300 font-mono truncate transition-colors duration-300 group-hover:text-white">
                      {ioc.ioc_value}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        copyToClipboard(ioc.ioc_value, ioc.id);
                      }}
                      className="opacity-0 group-hover:opacity-100 text-gray-400 hover:text-cyan-400 transition-all duration-300 hover:scale-110 relative z-50"
                      style={{ pointerEvents: 'auto' }}
                    >
                      {copiedId === ioc.id ? (
                        <Check className="w-4 h-4 text-green-400" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </td>

                {/* Threat Info */}
                <td className="px-6 py-4">
                  <div>
                    <div className="text-sm font-medium text-white transition-colors duration-300 group-hover:text-purple-400">
                      {ioc.threat_name || "Unknown"}
                    </div>
                    {ioc.threat_type && (
                      <div className="text-xs text-gray-400 capitalize transition-colors duration-300 group-hover:text-gray-300">
                        {ioc.threat_type}
                      </div>
                    )}
                  </div>
                </td>

                {/* Severity */}
                <td className="px-6 py-4 whitespace-nowrap">
                  <span
                    className={`
                      inline-flex items-center px-3 py-1 rounded-full text-xs
                      font-medium border capitalize ${getSeverityColor(ioc.severity)}
                      transition-all duration-300 group-hover:scale-110
                      ${ioc.severity === 'critical' ? 'group-hover:shadow-lg group-hover:shadow-red-500/50' : ''}
                      ${ioc.severity === 'high' ? 'group-hover:shadow-lg group-hover:shadow-orange-500/50' : ''}
                      relative
                    `}
                  >
                    {ioc.severity === 'critical' && (
                      <span className="absolute -top-1 -right-1 flex h-2 w-2">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                      </span>
                    )}
                    {ioc.severity}
                  </span>
                </td>

                {/* Confidence */}
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    <div className="w-full max-w-[80px] bg-gray-700 rounded-full h-2 overflow-hidden relative group-hover:shadow-md">
                      {/* Shimmer effect */}
                      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-shimmer" />
                      </div>
                      
                      <div
                        className="bg-cyan-500 h-2 rounded-full transition-all duration-500 group-hover:shadow-cyan-500/50"
                        style={{ 
                          width: `${ioc.confidence}%`,
                          animation: 'fillBar 1s ease-out'
                        }}
                      />
                    </div>
                    <span className="text-sm text-gray-300 font-medium transition-all duration-300 group-hover:text-white group-hover:font-semibold">
                      {ioc.confidence}%
                    </span>
                  </div>
                </td>

                {/* Source */}
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="text-sm text-gray-300 transition-colors duration-300 group-hover:text-blue-400">
                    {ioc.source}
                  </span>
                </td>

                {/* First Seen */}
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="text-sm text-gray-400 transition-colors duration-300 group-hover:text-gray-300">
                    {formatDate(ioc.first_seen)}
                  </span>
                </td>

                {/* Actions */}
                <td className="px-6 py-4 whitespace-nowrap">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedIOC(ioc);
                    }}
                    className="text-cyan-400 hover:text-cyan-300 transition-all duration-300 hover:scale-110 relative z-50"
                    style={{ pointerEvents: 'auto' }}
                  >
                    <ExternalLink className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Details Modal */}
      {selectedIOC && (
        <div
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-in fade-in duration-200"
          onClick={() => setSelectedIOC(null)}
        >
          <div
            className="bg-gray-800 border-2 border-gray-700 rounded-xl p-6 max-w-2xl w-full
                       max-h-[80vh] overflow-y-auto animate-in zoom-in slide-in-from-bottom-4 duration-300
                       shadow-2xl shadow-purple-500/20"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between mb-6">
              <div>
                <h3 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent mb-2">
                  IOC Details
                </h3>
                <p className="text-gray-400 text-sm">
                  ID: {selectedIOC.id}
                </p>
              </div>
              <button
                onClick={() => setSelectedIOC(null)}
                className="text-gray-400 hover:text-white transition-all duration-300 hover:rotate-90 hover:scale-110"
              >
                <span className="text-2xl">×</span>
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-sm text-gray-400 block mb-1">IOC Value</label>
                <div className="bg-gray-900/50 rounded-lg p-3 font-mono text-white break-all border border-gray-700 transition-all duration-300 hover:border-cyan-500/50">
                  {selectedIOC.ioc_value}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-gray-400 block mb-1">Type</label>
                  <div className="text-white capitalize font-medium">{selectedIOC.ioc_type}</div>
                </div>
                <div>
                  <label className="text-sm text-gray-400 block mb-1">Severity</label>
                  <span
                    className={`inline-flex items-center px-3 py-1 rounded-full text-xs
                              font-medium border capitalize ${getSeverityColor(selectedIOC.severity)}`}
                  >
                    {selectedIOC.severity}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-gray-400 block mb-1">Confidence</label>
                  <div className="text-white font-medium">{selectedIOC.confidence}%</div>
                </div>
                <div>
                  <label className="text-sm text-gray-400 block mb-1">Source</label>
                  <div className="text-white font-medium">{selectedIOC.source}</div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-gray-400 block mb-1">First Seen</label>
                  <div className="text-white">{formatDate(selectedIOC.first_seen)}</div>
                </div>
                <div>
                  <label className="text-sm text-gray-400 block mb-1">Last Seen</label>
                  <div className="text-white">{formatDate(selectedIOC.last_seen)}</div>
                </div>
              </div>

              <div>
                <label className="text-sm text-gray-400 block mb-1">Times Seen</label>
                <div className="text-white font-medium">{selectedIOC.times_seen}</div>
              </div>

              {selectedIOC.description && (
                <div>
                  <label className="text-sm text-gray-400 block mb-1">Description</label>
                  <div className="bg-gray-900/50 rounded-lg p-3 text-white border border-gray-700 transition-all duration-300 hover:border-purple-500/50">
                    {selectedIOC.description}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}