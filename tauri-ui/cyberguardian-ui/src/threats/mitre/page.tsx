"use client";

import { useState, useEffect } from "react";
import { Shield, Target, Info } from "lucide-react";
import MITREMatrix from "@/components/threats/MITREMatrix";
import MITREStats from "@/components/threats/MITREStats";
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

interface Stats {
  total_tactics: number;
  total_techniques: number;
  total_mappings: number;
  top_mapped_techniques: Array<{
    technique_id: string;
    name: string;
    count: number;
  }>;
}

export default function MITREPage() {
  const [matrixData, setMatrixData] = useState<MatrixData[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState<Technique | null>(null);

  useEffect(() => {
    fetchMatrix();
    fetchStats();
  }, []);

  const fetchMatrix = async () => {
    setLoading(true);
    try {
      const data = await fetchWithAuth('/api/mitre/matrix');

      if (data.success) {
        setMatrixData(data.matrix || []);
      }
    } catch (error) {
      console.error("Failed to fetch MITRE matrix:", error);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const data = await fetchWithAuth('/api/mitre/statistics');

      if (data.success) {
        setStats(data.statistics);
      }
    } catch (error) {
      console.error("Failed to fetch stats:", error);
    }
  };

  const handleRefresh = () => {
    fetchMatrix();
    fetchStats();
  };

  return (
    <ProtectedRoute>
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Shield className="w-8 h-8 text-cyan-400" />
            MITRE ATT&CK Matrix
          </h1>
          <p className="text-gray-400 mt-1">
            Adversarial Tactics, Techniques & Common Knowledge
          </p>
        </div>

        <button
          onClick={handleRefresh}
          className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg 
                     transition-all duration-200 flex items-center gap-2"
        >
          <Target className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Statistics */}
      <MITREStats stats={stats} loading={loading} />

      {/* Matrix Grid */}
      <MITREMatrix
        matrixData={matrixData}
        loading={loading}
        onTechniqueClick={setSelectedTechnique}
      />

      {/* Technique Details Modal */}
      {selectedTechnique && (
        <div
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={() => setSelectedTechnique(null)}
        >
          <div
            className="bg-gray-800 border border-gray-700 rounded-xl p-6 max-w-2xl w-full 
                       max-h-[80vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between mb-6">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <span className="px-3 py-1 bg-cyan-500/20 border border-cyan-500/30 
                                 rounded-lg text-cyan-400 font-mono text-sm">
                    {selectedTechnique.technique_id}
                  </span>
                </div>
                <h3 className="text-2xl font-bold text-white">
                  {selectedTechnique.name}
                </h3>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <span className="text-2xl">×</span>
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-sm text-gray-400 block mb-2">Description</label>
                <p className="text-gray-300 leading-relaxed">
                  {selectedTechnique.description}
                </p>
              </div>

              {selectedTechnique.platforms && selectedTechnique.platforms.length > 0 && (
                <div>
                  <label className="text-sm text-gray-400 block mb-2">Platforms</label>
                  <div className="flex flex-wrap gap-2">
                    {selectedTechnique.platforms.map((platform, idx) => (
                      <span
                        key={idx}
                        className="px-3 py-1 bg-purple-500/20 border border-purple-500/30 
                                 rounded-full text-sm text-purple-400"
                      >
                        {platform}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* ✅ Fixed Section */}
              <div>
                <label className="text-sm text-gray-400 block mb-2">
                  MITRE ATT&CK Reference
                </label>

                {selectedTechnique.url && (
                  <a
                    href={selectedTechnique.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-2"
                  >
                    View on MITRE ATT&CK
                    <Info className="w-4 h-4" />
                  </a>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
    </ProtectedRoute>
  );
}
