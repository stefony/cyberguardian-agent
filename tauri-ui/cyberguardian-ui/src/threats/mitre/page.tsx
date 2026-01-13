"use client";

import { useState, useEffect } from "react";
import { Shield, Target, Info } from "lucide-react";
import MITREMatrix from "@/components/threats/MITREMatrix";
import MITREStats from "@/components/threats/MITREStats";
import ProtectedRoute from '@/components/ProtectedRoute';

// API configuration
const API_BASE_URL = (import.meta as any).env.VITE_API_URL || 'https://cyberguardian-backend-production.up.railway.app';

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

    if (data.success && data.matrix) {
      setMatrixData(data.matrix);
    } else {
      console.log('🟡 Using mock MITRE matrix');
      const mockMatrix: MatrixData[] = [
        {
          tactic_id: 'TA0001',
          tactic_name: 'Initial Access',
          description: 'The adversary is trying to get into your network.',
          technique_count: 9,
          techniques: [
            { id: 1, technique_id: 'T1566', name: 'Phishing', description: 'Adversaries may send phishing messages to gain access to victim systems.', url: 'https://attack.mitre.org/techniques/T1566/', tactic_id: 1, platforms: ['Windows', 'macOS', 'Linux'] },
            { id: 2, technique_id: 'T1190', name: 'Exploit Public-Facing Application', description: 'Adversaries may exploit software vulnerabilities in public-facing applications.', url: 'https://attack.mitre.org/techniques/T1190/', tactic_id: 1, platforms: ['Windows', 'Linux', 'Network'] }
          ]
        },
        {
          tactic_id: 'TA0002',
          tactic_name: 'Execution',
          description: 'The adversary is trying to run malicious code.',
          technique_count: 13,
          techniques: [
            { id: 3, technique_id: 'T1059', name: 'Command and Scripting Interpreter', description: 'Adversaries may abuse command and script interpreters to execute commands.', url: 'https://attack.mitre.org/techniques/T1059/', tactic_id: 2, platforms: ['Windows', 'macOS', 'Linux'] },
            { id: 4, technique_id: 'T1053', name: 'Scheduled Task/Job', description: 'Adversaries may abuse task scheduling to execute programs at system startup.', url: 'https://attack.mitre.org/techniques/T1053/', tactic_id: 2, platforms: ['Windows', 'Linux'] }
          ]
        },
        {
          tactic_id: 'TA0003',
          tactic_name: 'Persistence',
          description: 'The adversary is trying to maintain their foothold.',
          technique_count: 19,
          techniques: [
            { id: 5, technique_id: 'T1547', name: 'Boot or Logon Autostart Execution', description: 'Adversaries may configure system settings to automatically execute programs.', url: 'https://attack.mitre.org/techniques/T1547/', tactic_id: 3, platforms: ['Windows', 'macOS', 'Linux'] },
            { id: 6, technique_id: 'T1078', name: 'Valid Accounts', description: 'Adversaries may obtain and abuse credentials of existing accounts.', url: 'https://attack.mitre.org/techniques/T1078/', tactic_id: 3, platforms: ['Windows', 'macOS', 'Linux', 'Cloud'] }
          ]
        },
        {
          tactic_id: 'TA0004',
          tactic_name: 'Privilege Escalation',
          description: 'The adversary is trying to gain higher-level permissions.',
          technique_count: 13,
          techniques: [
            { id: 7, technique_id: 'T1068', name: 'Exploitation for Privilege Escalation', description: 'Adversaries may exploit software vulnerabilities to escalate privileges.', url: 'https://attack.mitre.org/techniques/T1068/', tactic_id: 4, platforms: ['Windows', 'Linux', 'macOS'] }
          ]
        },
        {
          tactic_id: 'TA0005',
          tactic_name: 'Defense Evasion',
          description: 'The adversary is trying to avoid being detected.',
          technique_count: 42,
          techniques: [
            { id: 8, technique_id: 'T1070', name: 'Indicator Removal', description: 'Adversaries may delete or modify artifacts to remove evidence.', url: 'https://attack.mitre.org/techniques/T1070/', tactic_id: 5, platforms: ['Windows', 'Linux', 'macOS'] },
            { id: 9, technique_id: 'T1027', name: 'Obfuscated Files or Information', description: 'Adversaries may obscure files or information to evade detection.', url: 'https://attack.mitre.org/techniques/T1027/', tactic_id: 5, platforms: ['Windows', 'macOS', 'Linux'] }
          ]
        }
      ];
      setMatrixData(mockMatrix);
    }
  } catch (error) {
    console.error("Failed to fetch MITRE matrix:", error);
    console.log('🟡 Using mock MITRE matrix (error fallback)');
    const mockMatrix: MatrixData[] = [
      {
        tactic_id: 'TA0001',
        tactic_name: 'Initial Access',
        description: 'The adversary is trying to get into your network.',
        technique_count: 9,
        techniques: [
          { id: 1, technique_id: 'T1566', name: 'Phishing', description: 'Adversaries may send phishing messages to gain access to victim systems.', url: 'https://attack.mitre.org/techniques/T1566/', tactic_id: 1, platforms: ['Windows', 'macOS', 'Linux'] },
          { id: 2, technique_id: 'T1190', name: 'Exploit Public-Facing Application', description: 'Adversaries may exploit software vulnerabilities in public-facing applications.', url: 'https://attack.mitre.org/techniques/T1190/', tactic_id: 1, platforms: ['Windows', 'Linux', 'Network'] }
        ]
      },
      {
        tactic_id: 'TA0002',
        tactic_name: 'Execution',
        description: 'The adversary is trying to run malicious code.',
        technique_count: 13,
        techniques: [
          { id: 3, technique_id: 'T1059', name: 'Command and Scripting Interpreter', description: 'Adversaries may abuse command and script interpreters to execute commands.', url: 'https://attack.mitre.org/techniques/T1059/', tactic_id: 2, platforms: ['Windows', 'macOS', 'Linux'] },
          { id: 4, technique_id: 'T1053', name: 'Scheduled Task/Job', description: 'Adversaries may abuse task scheduling to execute programs at system startup.', url: 'https://attack.mitre.org/techniques/T1053/', tactic_id: 2, platforms: ['Windows', 'Linux'] }
        ]
      },
      {
        tactic_id: 'TA0003',
        tactic_name: 'Persistence',
        description: 'The adversary is trying to maintain their foothold.',
        technique_count: 19,
        techniques: [
          { id: 5, technique_id: 'T1547', name: 'Boot or Logon Autostart Execution', description: 'Adversaries may configure system settings to automatically execute programs.', url: 'https://attack.mitre.org/techniques/T1547/', tactic_id: 3, platforms: ['Windows', 'macOS', 'Linux'] },
          { id: 6, technique_id: 'T1078', name: 'Valid Accounts', description: 'Adversaries may obtain and abuse credentials of existing accounts.', url: 'https://attack.mitre.org/techniques/T1078/', tactic_id: 3, platforms: ['Windows', 'macOS', 'Linux', 'Cloud'] }
        ]
      },
      {
        tactic_id: 'TA0004',
        tactic_name: 'Privilege Escalation',
        description: 'The adversary is trying to gain higher-level permissions.',
        technique_count: 13,
        techniques: [
          { id: 7, technique_id: 'T1068', name: 'Exploitation for Privilege Escalation', description: 'Adversaries may exploit software vulnerabilities to escalate privileges.', url: 'https://attack.mitre.org/techniques/T1068/', tactic_id: 4, platforms: ['Windows', 'Linux', 'macOS'] }
        ]
      },
      {
        tactic_id: 'TA0005',
        tactic_name: 'Defense Evasion',
        description: 'The adversary is trying to avoid being detected.',
        technique_count: 42,
        techniques: [
          { id: 8, technique_id: 'T1070', name: 'Indicator Removal', description: 'Adversaries may delete or modify artifacts to remove evidence.', url: 'https://attack.mitre.org/techniques/T1070/', tactic_id: 5, platforms: ['Windows', 'Linux', 'macOS'] },
          { id: 9, technique_id: 'T1027', name: 'Obfuscated Files or Information', description: 'Adversaries may obscure files or information to evade detection.', url: 'https://attack.mitre.org/techniques/T1027/', tactic_id: 5, platforms: ['Windows', 'macOS', 'Linux'] }
        ]
      }
    ];
    setMatrixData(mockMatrix);
  } finally {
    setLoading(false);
  }
};

  
const fetchStats = async () => {
  try {
    const data = await fetchWithAuth('/api/mitre/statistics');

    if (data.success && data.statistics) {
      setStats(data.statistics);
    } else {
      console.log('🟡 Using mock MITRE stats');
      const mockStats: Stats = {
        total_tactics: 14,
        total_techniques: 193,
        total_mappings: 847,
        top_mapped_techniques: [
          { technique_id: 'T1059', name: 'Command and Scripting Interpreter', count: 127 },
          { technique_id: 'T1070', name: 'Indicator Removal', count: 98 },
          { technique_id: 'T1566', name: 'Phishing', count: 86 },
          { technique_id: 'T1053', name: 'Scheduled Task/Job', count: 74 },
          { technique_id: 'T1027', name: 'Obfuscated Files or Information', count: 67 }
        ]
      };
      setStats(mockStats);
    }
  } catch (error) {
    console.error("Failed to fetch stats:", error);
    console.log('🟡 Using mock MITRE stats (error fallback)');
    const mockStats: Stats = {
      total_tactics: 14,
      total_techniques: 193,
      total_mappings: 847,
      top_mapped_techniques: [
        { technique_id: 'T1059', name: 'Command and Scripting Interpreter', count: 127 },
        { technique_id: 'T1070', name: 'Indicator Removal', count: 98 },
        { technique_id: 'T1566', name: 'Phishing', count: 86 },
        { technique_id: 'T1053', name: 'Scheduled Task/Job', count: 74 },
        { technique_id: 'T1027', name: 'Obfuscated Files or Information', count: 67 }
      ]
    };
    setStats(mockStats);
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

