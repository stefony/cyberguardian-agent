'use client'

import { useState } from 'react'
import { Upload, FileSearch, AlertTriangle, CheckCircle2, Shield, Cpu, Zap } from 'lucide-react'

type ScanResult = {
  filename: string
  file_size: number
  is_malware: boolean
  confidence_score: number
  threat_level: 'safe' | 'suspicious' | 'dangerous' | 'critical'
  yara_detected: boolean
  yara_matches: string[]
  heuristic_detected: boolean
  heuristic_indicators: string[]
  ml_detected: boolean
  detection_methods: string[]
  threat_indicators: string[]
  recommendation: string
  timestamp: string
}

export default function FileScanner() {
  const [file, setFile] = useState<File | null>(null)
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0]
    if (selectedFile) {
      setFile(selectedFile)
      setResult(null)
      setError(null)
    }
  }

  const handleScan = async () => {
    if (!file) return

    setScanning(true)
    setError(null)
    setResult(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/signatures/detect/upload`,
        {
          method: 'POST',
          body: formData,
        }
      )

      if (!response.ok) {
        throw new Error('Scan failed')
      }

      const data = await response.json()
      setResult(data)
    } catch (err: any) {
      setError(err.message || 'Failed to scan file')
    } finally {
      setScanning(false)
    }
  }

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'critical': return 'red'
      case 'dangerous': return 'orange'
      case 'suspicious': return 'yellow'
      default: return 'green'
    }
  }

  const getThreatGradient = (level: string) => {
    switch (level) {
      case 'critical': return 'from-red-500 to-red-700'
      case 'dangerous': return 'from-orange-500 to-red-500'
      case 'suspicious': return 'from-yellow-500 to-orange-500'
      default: return 'from-green-500 to-emerald-500'
    }
  }

  return (
    <div className="space-y-6">
      {/* Upload Section */}
      <div className="relative group">
        <div className="absolute -inset-0.5 bg-gradient-to-r from-purple-500 to-pink-500 rounded-xl opacity-20 group-hover:opacity-30 blur transition duration-300" />
        
        <div className="relative p-6 bg-dark-card/90 backdrop-blur-xl border-2 border-dark-border/50 hover:border-dark-border rounded-xl">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-gradient-to-br from-purple-500 to-pink-500 rounded-xl shadow-lg">
              <Upload className="w-6 h-6 text-white" />
            </div>
            <div>
              <h3 className="text-xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
                Multi-Engine File Scanner
              </h3>
              <p className="text-sm text-gray-400">
                Advanced detection with YARA + Heuristics + ML
              </p>
            </div>
          </div>

          {/* File Input */}
          <div className="mb-4">
            <label
              htmlFor="file-upload"
              className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed border-dark-border rounded-xl cursor-pointer hover:border-purple-500/50 transition-colors"
            >
              <div className="flex flex-col items-center justify-center pt-5 pb-6">
                <FileSearch className="w-10 h-10 text-gray-400 mb-2" />
                <p className="text-sm text-gray-400">
                  {file ? file.name : 'Click to upload or drag and drop'}
                </p>
                <p className="text-xs text-gray-500 mt-1">
                  Any file type supported
                </p>
              </div>
              <input
                id="file-upload"
                type="file"
                className="hidden"
                onChange={handleFileChange}
              />
            </label>
          </div>

          {/* Scan Button */}
          {file && (
            <button
              onClick={handleScan}
              disabled={scanning}
              className={`w-full px-4 py-3 rounded-xl font-bold text-white shadow-lg transition-all duration-300 ${
                scanning
                  ? 'bg-gray-600 cursor-not-allowed'
                  : 'bg-gradient-to-r from-purple-500 to-pink-500 hover:scale-[1.02] active:scale-[0.98]'
              }`}
            >
              {scanning ? (
                <div className="flex items-center justify-center gap-2">
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Scanning with 3 engines...
                </div>
              ) : (
                <div className="flex items-center justify-center gap-2">
                  <Shield className="w-5 h-5" />
                  Start Multi-Engine Scan
                </div>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-4 bg-red-500/10 border-2 border-red-500/30 rounded-xl">
          <div className="flex items-center gap-2 text-red-400">
            <AlertTriangle className="w-5 h-5" />
            <span className="font-medium">{error}</span>
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Threat Level Card */}
          <div className={`relative group`}>
            <div className={`absolute -inset-0.5 bg-gradient-to-r ${getThreatGradient(result.threat_level)} rounded-xl opacity-30 blur transition duration-300`} />
            
            <div className="relative p-6 bg-dark-card/90 backdrop-blur-xl border-2 border-dark-border/50 rounded-xl">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h4 className="text-lg font-bold text-white mb-1">Scan Results</h4>
                  <p className="text-sm text-gray-400">{result.filename}</p>
                </div>
                <div className={`px-4 py-2 rounded-xl bg-gradient-to-r ${getThreatGradient(result.threat_level)} shadow-lg`}>
                  <span className="text-white font-bold uppercase text-sm">
                    {result.threat_level}
                  </span>
                </div>
              </div>

              {/* Confidence Score */}
              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-400">Confidence Score</span>
                  <span className="text-lg font-bold text-white">
                    {(result.confidence_score * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="w-full h-3 bg-dark-bg/50 rounded-full overflow-hidden">
                  <div
                    className={`h-full bg-gradient-to-r ${getThreatGradient(result.threat_level)} transition-all duration-500`}
                    style={{ width: `${result.confidence_score * 100}%` }}
                  />
                </div>
              </div>

              {/* Detection Methods */}
              <div className="grid grid-cols-3 gap-3 mb-4">
                <div className={`p-3 rounded-lg border-2 ${
                  result.yara_detected 
                    ? 'bg-red-500/10 border-red-500/30' 
                    : 'bg-dark-bg/50 border-dark-border/50'
                }`}>
                  <div className="flex items-center gap-2 mb-1">
                    <Shield className={`w-4 h-4 ${result.yara_detected ? 'text-red-400' : 'text-gray-500'}`} />
                    <span className="text-xs font-semibold text-white">YARA</span>
                  </div>
                  <span className={`text-xs ${result.yara_detected ? 'text-red-400' : 'text-gray-500'}`}>
                    {result.yara_detected ? `${result.yara_matches.length} matches` : 'Clean'}
                  </span>
                </div>

                <div className={`p-3 rounded-lg border-2 ${
                  result.heuristic_detected 
                    ? 'bg-orange-500/10 border-orange-500/30' 
                    : 'bg-dark-bg/50 border-dark-border/50'
                }`}>
                  <div className="flex items-center gap-2 mb-1">
                    <Cpu className={`w-4 h-4 ${result.heuristic_detected ? 'text-orange-400' : 'text-gray-500'}`} />
                    <span className="text-xs font-semibold text-white">Heuristic</span>
                  </div>
                  <span className={`text-xs ${result.heuristic_detected ? 'text-orange-400' : 'text-gray-500'}`}>
                    {result.heuristic_detected ? `${result.heuristic_indicators.length} indicators` : 'Clean'}
                  </span>
                </div>

                <div className={`p-3 rounded-lg border-2 ${
                  result.ml_detected 
                    ? 'bg-purple-500/10 border-purple-500/30' 
                    : 'bg-dark-bg/50 border-dark-border/50'
                }`}>
                  <div className="flex items-center gap-2 mb-1">
                    <Zap className={`w-4 h-4 ${result.ml_detected ? 'text-purple-400' : 'text-gray-500'}`} />
                    <span className="text-xs font-semibold text-white">ML</span>
                  </div>
                  <span className={`text-xs ${result.ml_detected ? 'text-purple-400' : 'text-gray-500'}`}>
                    {result.ml_detected ? 'Detected' : 'Clean'}
                  </span>
                </div>
              </div>

              {/* Recommendation */}
              <div className={`p-4 rounded-lg border-2 ${
                result.is_malware 
                  ? 'bg-red-500/10 border-red-500/30' 
                  : 'bg-green-500/10 border-green-500/30'
              }`}>
                <div className="flex items-start gap-3">
                  {result.is_malware ? (
                    <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                  ) : (
                    <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                  )}
                  <div>
                    <h5 className={`font-semibold mb-1 ${result.is_malware ? 'text-red-400' : 'text-green-400'}`}>
                      Recommendation
                    </h5>
                    <p className="text-sm text-gray-300">{result.recommendation}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Threat Indicators */}
          {result.threat_indicators.length > 0 && (
            <div className="p-6 bg-dark-card/90 backdrop-blur-xl border-2 border-dark-border/50 rounded-xl">
              <h4 className="text-lg font-bold text-white mb-3">Threat Indicators</h4>
              <div className="space-y-2">
                {result.threat_indicators.map((indicator, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-sm">
                    <AlertTriangle className="w-4 h-4 text-orange-400 flex-shrink-0 mt-0.5" />
                    <span className="text-gray-300">{indicator}</span>
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