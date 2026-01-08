'use client'

import { useState } from 'react'
import { api } from '@/lib/api'
import { AlertTriangle, Cpu, HardDrive, Network, Activity } from 'lucide-react'

export default function WhatIfPanel() {
  const [threatsPerHour, setThreatsPerHour] = useState(100)
  const [durationHours, setDurationHours] = useState(24)
  const [defenses, setDefenses] = useState({
    firewall: true,
    ids: false,
    waf: false,
    honeypots: true,
  })
  const [loading, setLoading] = useState(false)
  const [prediction, setPrediction] = useState<any>(null)

  const runSimulation = async () => {
    setLoading(true)
    try {
      const response = await api.whatIf.simulate({
        threats_per_hour: threatsPerHour,
        attack_types: ['brute_force', 'malware', 'ddos'],
        duration_hours: durationHours,
        current_defenses: defenses,
      })

      if (response.success && response.data) {
        setPrediction(response.data)
      }
    } catch (error) {
      console.error('Simulation failed:', error)
    } finally {
      setLoading(false)
    }
  }

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-500'
      case 'high': return 'text-orange-500'
      case 'medium': return 'text-yellow-500'
      case 'low': return 'text-green-500'
      default: return 'text-gray-500'
    }
  }

  return (
    <div className="space-y-6">
      {/* Input Panel */}
      <div className="p-6 bg-dark-card border border-dark-border rounded-xl">
        <h3 className="text-xl font-bold mb-4 text-dark-text">Scenario Parameters</h3>
        
        {/* Threats Per Hour */}
        <div className="mb-4">
          <label className="block text-sm font-medium text-dark-text/70 mb-2">
            Threats Per Hour: {threatsPerHour}
          </label>
          <input
            type="range"
            min="10"
            max="1000"
            step="10"
            value={threatsPerHour}
            onChange={(e) => setThreatsPerHour(Number(e.target.value))}
            className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer"
          />
        </div>

        {/* Duration */}
        <div className="mb-4">
          <label className="block text-sm font-medium text-dark-text/70 mb-2">
            Duration (hours): {durationHours}
          </label>
          <input
            type="range"
            min="1"
            max="168"
            value={durationHours}
            onChange={(e) => setDurationHours(Number(e.target.value))}
            className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer"
          />
        </div>

        {/* Defense Toggles */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-dark-text/70 mb-3">
            Active Defenses:
          </label>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(defenses).map(([key, value]) => (
              <label key={key} className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={value}
                  onChange={(e) => setDefenses({ ...defenses, [key]: e.target.checked })}
                  className="w-4 h-4 text-purple-600 bg-gray-700 border-gray-600 rounded focus:ring-purple-500"
                />
                <span className="text-sm text-dark-text capitalize">{key}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Simulate Button */}
        <button
          onClick={runSimulation}
          disabled={loading}
          className="w-full px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 rounded-lg font-semibold transition-all"
        >
          {loading ? 'Simulating...' : '🔮 Run Simulation'}
        </button>
      </div>

      {/* Results Panel */}
      {prediction && (
        <div className="space-y-4">
          {/* Threat Summary */}
          <div className="p-6 bg-dark-card border border-dark-border rounded-xl">
            <h3 className="text-xl font-bold mb-4 text-dark-text">Prediction Results</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div className="p-4 bg-dark-bg rounded-lg">
                <p className="text-sm text-dark-text/70 mb-1">Total Threats</p>
                <p className="text-2xl font-bold text-dark-text">{prediction.threat_volume.toLocaleString()}</p>
              </div>
              <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
                <p className="text-sm text-dark-text/70 mb-1">Blocked</p>
                <p className="text-2xl font-bold text-green-500">{prediction.estimated_blocks.toLocaleString()}</p>
              </div>
              <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                <p className="text-sm text-dark-text/70 mb-1">Breaches</p>
                <p className="text-2xl font-bold text-red-500">{prediction.estimated_breaches.toLocaleString()}</p>
              </div>
            </div>

            {/* Risk Level */}
            <div className="p-4 bg-dark-bg rounded-lg">
              <div className="flex items-center justify-between">
                <span className="text-sm text-dark-text/70">Risk Level:</span>
                <span className={`text-lg font-bold uppercase ${getRiskColor(prediction.risk_level)}`}>
                  {prediction.risk_level}
                </span>
              </div>
              <div className="flex items-center justify-between mt-2">
                <span className="text-sm text-dark-text/70">Confidence:</span>
                <span className="text-lg font-bold text-dark-text">{(prediction.confidence * 100).toFixed(0)}%</span>
              </div>
            </div>
          </div>

          {/* Resource Impact */}
          <div className="p-6 bg-dark-card border border-dark-border rounded-xl">
            <h3 className="text-xl font-bold mb-4 text-dark-text">Resource Impact</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-dark-bg rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <Cpu className="w-5 h-5 text-blue-500" />
                  <span className="text-sm text-dark-text/70">CPU Usage</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-blue-500" 
                      style={{ width: `${prediction.cpu_usage_percent}%` }}
                    />
                  </div>
                  <span className="text-lg font-bold text-dark-text">{prediction.cpu_usage_percent}%</span>
                </div>
              </div>

              <div className="p-4 bg-dark-bg rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <Activity className="w-5 h-5 text-green-500" />
                  <span className="text-sm text-dark-text/70">Memory Usage</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-green-500" 
                      style={{ width: `${prediction.memory_usage_percent}%` }}
                    />
                  </div>
                  <span className="text-lg font-bold text-dark-text">{prediction.memory_usage_percent}%</span>
                </div>
              </div>

              <div className="p-4 bg-dark-bg rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <HardDrive className="w-5 h-5 text-purple-500" />
                  <span className="text-sm text-dark-text/70">Disk I/O</span>
                </div>
                <p className="text-lg font-bold text-dark-text">{prediction.disk_io_mbps} MB/s</p>
              </div>

              <div className="p-4 bg-dark-bg rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <Network className="w-5 h-5 text-cyan-500" />
                  <span className="text-sm text-dark-text/70">Network Bandwidth</span>
                </div>
                <p className="text-lg font-bold text-dark-text">{prediction.network_bandwidth_mbps} Mbps</p>
              </div>
            </div>
          </div>

          {/* Recommendations */}
          {prediction.recommendations.length > 0 && (
            <div className="p-6 bg-dark-card border border-dark-border rounded-xl">
              <h3 className="text-xl font-bold mb-4 text-dark-text">AI Recommendations</h3>
              <div className="space-y-2">
                {prediction.recommendations.map((rec: string, index: number) => (
                  <div key={index} className="flex items-start gap-3 p-3 bg-dark-bg rounded-lg">
                    <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                    <p className="text-sm text-dark-text/90">{rec}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}