"use client";

import { Filter } from "lucide-react";

interface IOCFiltersProps {
  selectedType: string;
  selectedSeverity: string;
  selectedSource: string;
  onTypeChange: (type: string) => void;
  onSeverityChange: (severity: string) => void;
  onSourceChange: (source: string) => void;
}

export default function IOCFilters({
  selectedType,
  selectedSeverity,
  selectedSource,
  onTypeChange,
  onSeverityChange,
  onSourceChange,
}: IOCFiltersProps) {
  const iocTypes = [
    { value: "all", label: "All Types" },
    { value: "ip", label: "IP Address" },
    { value: "domain", label: "Domain" },
    { value: "hash", label: "File Hash" },
    { value: "url", label: "URL" },
    { value: "email", label: "Email" },
  ];

  const severityLevels = [
    { value: "all", label: "All Severities" },
    { value: "low", label: "Low", color: "text-green-400" },
    { value: "medium", label: "Medium", color: "text-yellow-400" },
    { value: "high", label: "High", color: "text-orange-400" },
    { value: "critical", label: "Critical", color: "text-red-400" },
  ];

  const sources = [
    { value: "all", label: "All Sources" },
    { value: "AbuseIPDB", label: "AbuseIPDB" },
    { value: "OTX", label: "AlienVault OTX" },
    { value: "manual", label: "Manual Entry" },
    { value: "internal", label: "Internal Detection" },
  ];

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6 transition-all duration-300 hover:border-gray-600">
      <div className="flex items-center gap-2 mb-4">
        <Filter className="w-5 h-5 text-cyan-400 transition-transform duration-300 hover:rotate-12" />
        <h3 className="text-lg font-semibold text-white">Filters</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* IOC Type Filter */}
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-2 transition-colors duration-300 hover:text-gray-300">
            IOC Type
          </label>
          <select
            value={selectedType}
            onChange={(e) => onTypeChange(e.target.value)}
            className="w-full bg-gray-900 border-2 border-gray-600 rounded-lg px-4 py-2.5
                     text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-400
                     transition-all duration-300 cursor-pointer
                     hover:border-cyan-500 hover:bg-cyan-500/5
                     appearance-none relative z-50"
            style={{ 
              pointerEvents: 'auto',
              colorScheme: 'dark'
            }}
          >
            {iocTypes.map((type) => (
              <option key={type.value} value={type.value} className="bg-[#0a0e27] text-white">
                {type.label}
              </option>
            ))}
          </select>
        </div>

        {/* Severity Filter */}
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-2 transition-colors duration-300 hover:text-gray-300">
            Severity Level
          </label>
          <select
            value={selectedSeverity}
            onChange={(e) => onSeverityChange(e.target.value)}
            className="w-full bg-gray-900 border-2 border-gray-600 rounded-lg px-4 py-2.5
                     text-white focus:ring-2 focus:ring-purple-500 focus:border-purple-400
                     transition-all duration-300 cursor-pointer
                     hover:border-purple-500 hover:bg-purple-500/5
                     appearance-none relative z-50"
            style={{ 
              pointerEvents: 'auto',
              colorScheme: 'dark'
            }}
          >
            {severityLevels.map((severity) => (
              <option key={severity.value} value={severity.value} className="bg-[#0a0e27] text-white">
                {severity.label}
              </option>
            ))}
          </select>
        </div>

        {/* Source Filter */}
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-2 transition-colors duration-300 hover:text-gray-300">
            Source
          </label>
          <select
            value={selectedSource}
            onChange={(e) => onSourceChange(e.target.value)}
            className="w-full bg-gray-900 border-2 border-gray-600 rounded-lg px-4 py-2.5
                     text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-400
                     transition-all duration-300 cursor-pointer
                     hover:border-blue-500 hover:bg-blue-500/5
                     appearance-none relative z-50"
            style={{ 
              pointerEvents: 'auto',
              colorScheme: 'dark'
            }}
          >
            {sources.map((source) => (
              <option key={source.value} value={source.value} className="bg-[#0a0e27] text-white">
                {source.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Active Filters Display */}
      {(selectedType !== "all" || selectedSeverity !== "all" || selectedSource !== "all") && (
        <div className="mt-4 pt-4 border-t border-gray-700 animate-in fade-in slide-in-from-top-2 duration-300">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm text-gray-400">Active filters:</span>

            {selectedType !== "all" && (
              <span className="px-3 py-1 bg-cyan-500/20 border border-cyan-500/30
                             rounded-full text-sm text-cyan-400 
                             transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-cyan-500/50
                             animate-in fade-in zoom-in duration-200">
                Type: {iocTypes.find(t => t.value === selectedType)?.label}
              </span>
            )}

            {selectedSeverity !== "all" && (
              <span className="px-3 py-1 bg-orange-500/20 border border-orange-500/30
                             rounded-full text-sm text-orange-400
                             transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-orange-500/50
                             animate-in fade-in zoom-in duration-200">
                Severity: {severityLevels.find(s => s.value === selectedSeverity)?.label}
              </span>
            )}

            {selectedSource !== "all" && (
              <span className="px-3 py-1 bg-purple-500/20 border border-purple-500/30
                             rounded-full text-sm text-purple-400
                             transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/50
                             animate-in fade-in zoom-in duration-200">
                Source: {sources.find(s => s.value === selectedSource)?.label}
              </span>
            )}

            <button
              onClick={() => {
                onTypeChange("all");
                onSeverityChange("all");
                onSourceChange("all");
              }}
              className="ml-auto px-3 py-1 text-sm text-gray-400 hover:text-white
                       transition-all duration-300 hover:scale-105
                       border border-transparent hover:border-gray-600 rounded-lg"
            >
              Clear all
            </button>
          </div>
        </div>
      )}
    </div>
  );
}