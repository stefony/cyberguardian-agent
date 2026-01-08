"use client";

import { ChevronRight, ExternalLink, Shield, Sparkles } from "lucide-react";

interface Technique {
  id: number;
  technique_id: string;
  name: string;
  description: string;
  url: string;
  tactic_id: number;
  platforms: string[];
}

interface MatrixData {
  tactic_id: string;
  tactic_name: string;
  description: string;
  technique_count: number;
  techniques: Technique[];
}

interface MITREMatrixProps {
  matrixData: MatrixData[];
  loading: boolean;
  onTechniqueClick: (technique: Technique) => void;
}

export default function MITREMatrix({
  matrixData,
  loading,
  onTechniqueClick,
}: MITREMatrixProps) {
  if (loading) {
    return (
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-700/50 rounded w-48 mb-6"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {[...Array(12)].map((_, i) => (
              <div key={i} className="h-64 bg-gray-700/50 rounded-lg"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (matrixData.length === 0) {
    return (
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-12 text-center relative overflow-hidden group">
        {/* Floating particles background */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-1/4 left-1/4 w-32 h-32 bg-cyan-500/5 rounded-full blur-3xl animate-float" />
          <div className="absolute bottom-1/4 right-1/4 w-40 h-40 bg-purple-500/5 rounded-full blur-3xl animate-float-delayed" />
          <div className="absolute top-1/2 right-1/3 w-36 h-36 bg-blue-500/5 rounded-full blur-3xl animate-float-slow" />
        </div>

        <div className="relative z-10">
          <div className="inline-flex items-center justify-center w-24 h-24 rounded-full bg-gradient-to-br from-cyan-500/20 to-purple-500/20 mb-6 animate-pulse">
            <Shield className="w-12 h-12 text-cyan-400" />
          </div>
          
          <h3 className="text-2xl font-bold text-white mb-3 bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
            No Matrix Data
          </h3>
          
          <p className="text-gray-400 mb-6 max-w-md mx-auto">
            MITRE ATT&CK matrix data is not available. The matrix will be populated when threat detection is active.
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

          {/* Info card */}
          <div className="mt-8 max-w-lg mx-auto bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
            <p className="text-sm text-blue-300 text-left">
              <strong className="text-blue-400">💡 What is MITRE ATT&CK?</strong><br/>
              A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. 
              It helps understand attacker behavior and improve defenses.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
          ATT&CK Matrix
        </h2>
        <span className="text-sm text-gray-400 px-4 py-2 bg-gray-800/50 border border-gray-700 rounded-lg">
          {matrixData.length} Tactics • {matrixData.reduce((acc, t) => acc + t.technique_count, 0)} Techniques
        </span>
      </div>

      {/* Horizontal Scrollable Matrix */}
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl overflow-hidden transition-all duration-300 hover:border-gray-600">
        <div className="overflow-x-auto">
          <div className="flex gap-4 p-6" style={{ minWidth: 'max-content' }}>
            {matrixData.map((tactic) => (
              <div
                key={tactic.tactic_id}
                className="flex-shrink-0 w-80 group/tactic"
              >
                {/* Tactic Header */}
                <div className="bg-gradient-to-br from-cyan-500/20 to-purple-500/20
                              border border-cyan-500/30 rounded-t-xl p-4 mb-2
                              transition-all duration-300
                              group-hover/tactic:border-cyan-500/50 group-hover/tactic:shadow-lg group-hover/tactic:shadow-cyan-500/20
                              relative overflow-hidden">
                  {/* Corner glow */}
                  <div className="absolute top-0 right-0 w-16 h-16 bg-gradient-to-br from-white/10 to-transparent rounded-bl-full opacity-0 group-hover/tactic:opacity-100 transition-opacity duration-300" />
                  
                  <div className="flex items-start justify-between mb-2 relative z-10">
                    <span className="text-xs font-mono text-cyan-400 px-2 py-1 bg-cyan-500/20 rounded border border-cyan-500/30 transition-all duration-300 group-hover/tactic:scale-105">
                      {tactic.tactic_id}
                    </span>
                    <span className="text-xs text-gray-400 px-2 py-1 bg-gray-800/50 rounded transition-colors duration-300 group-hover/tactic:text-cyan-400">
                      {tactic.technique_count} techniques
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-white mb-1 transition-colors duration-300 group-hover/tactic:text-cyan-400">
                    {tactic.tactic_name}
                  </h3>
                  <p className="text-xs text-gray-400 line-clamp-2 transition-colors duration-300 group-hover/tactic:text-gray-300">
                    {tactic.description}
                  </p>
                </div>

                {/* Techniques List */}
                <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2
                              scrollbar-thin scrollbar-thumb-gray-600 scrollbar-track-gray-800">
                  {tactic.techniques.map((technique) => (
                    <button
                      key={technique.id}
                      onClick={() => onTechniqueClick(technique)}
                      className="w-full bg-gray-900/50 hover:bg-gray-700/50 border border-gray-700
                               hover:border-cyan-500/50 rounded-lg p-3 transition-all duration-300
                               text-left group/technique
                               hover:scale-[1.02] hover:shadow-lg hover:shadow-cyan-500/20"
                    >
                      <div className="flex items-start justify-between mb-1">
                        <span className="text-xs font-mono text-purple-400 px-2 py-0.5 bg-purple-500/20 rounded border border-purple-500/30 transition-all duration-300 group-hover/technique:scale-105 group-hover/technique:shadow-lg group-hover/technique:shadow-purple-500/50">
                          {technique.technique_id}
                        </span>
                        <ChevronRight className="w-4 h-4 text-gray-400 group-hover/technique:text-cyan-400
                                                 transition-all duration-300 group-hover/technique:translate-x-1" />
                      </div>
                      <h4 className="text-sm font-medium text-white mb-1 line-clamp-2
                                   group-hover/technique:text-cyan-400 transition-colors duration-300">
                        {technique.name}
                      </h4>
                      {technique.platforms && technique.platforms.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {technique.platforms.slice(0, 3).map((platform, idx) => (
                            <span
                              key={idx}
                              className="text-xs px-2 py-0.5 bg-gray-800 text-gray-400
                                       rounded border border-gray-700 transition-all duration-300
                                       group-hover/technique:border-gray-600 group-hover/technique:text-gray-300"
                            >
                              {platform}
                            </span>
                          ))}
                          {technique.platforms.length > 3 && (
                            <span className="text-xs px-2 py-0.5 text-gray-500 transition-colors duration-300 group-hover/technique:text-gray-400">
                              +{technique.platforms.length - 3}
                            </span>
                          )}
                        </div>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Legend */}
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4 transition-all duration-300 hover:border-gray-600">
        <div className="flex items-center gap-6 text-sm flex-wrap">
          <div className="flex items-center gap-2 group/legend">
            <div className="w-3 h-3 bg-cyan-500 rounded transition-all duration-300 group-hover/legend:scale-110 group-hover/legend:shadow-lg group-hover/legend:shadow-cyan-500/50"></div>
            <span className="text-gray-400 transition-colors duration-300 group-hover/legend:text-gray-300">Tactic</span>
          </div>
          <div className="flex items-center gap-2 group/legend">
            <div className="w-3 h-3 bg-purple-500 rounded transition-all duration-300 group-hover/legend:scale-110 group-hover/legend:shadow-lg group-hover/legend:shadow-purple-500/50"></div>
            <span className="text-gray-400 transition-colors duration-300 group-hover/legend:text-gray-300">Technique ID</span>
          </div>
          <div className="flex items-center gap-2 group/legend">
            <ExternalLink className="w-3 h-3 text-gray-400 transition-all duration-300 group-hover/legend:text-cyan-400 group-hover/legend:scale-110" />
            <span className="text-gray-400 transition-colors duration-300 group-hover/legend:text-gray-300">Click for details</span>
          </div>
        </div>
      </div>
    </div>
  );
}