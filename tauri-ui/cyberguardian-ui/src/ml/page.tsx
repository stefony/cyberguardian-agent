'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import CountUp from 'react-countup'
import { RefreshCw, Brain, TrendingUp, CheckCircle, Zap, Activity, AlertTriangle } from 'lucide-react'
import { mlApi } from '@/lib/api'
import ProtectedRoute from '@/components/ProtectedRoute';

// ==== Types ====
interface ModelStatus {
  model_trained: boolean
  training_date: string | null
  training_samples: number
  anomaly_detector_available: boolean
  behavior_clusterer_available: boolean
  feature_count: number
  features: string[]
}

interface ThreatScore {
  threat_score: number
  threat_level: 'low' | 'medium' | 'high' | 'critical' | string
  is_anomaly: boolean
  anomaly_score: number
  behavior_cluster: string
  confidence: number
}

interface Metrics {
  trained: boolean
  samples: number
  n_clusters?: number
  silhouette?: number
  mean_anomaly?: number
  labeled_count: number
  classifier_available: boolean
  training_date?: string | null
}

export default function MLPage() {
  // Base state
  const [status, setStatus] = useState<ModelStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [training, setTraining] = useState(false)
  const [testResult, setTestResult] = useState<ThreatScore | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Test inputs
  const [testIP, setTestIP] = useState('192.168.1.100')
  const [testPayload, setTestPayload] = useState('GET /api/data')

  // Advanced ML state
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [threshold, setThreshold] = useState<number>(1.0)
  const [saving, setSaving] = useState(false)
  const [loadingModel, setLoadingModel] = useState(false)
  const minT = 0.1
  const maxT = 1.5

  // ---------- init ----------
  useEffect(() => {
    fetchStatus()

    ;(async () => {
      const m = await mlApi.getMetrics()
      if (m.success && m.data) setMetrics(m.data)

      const t = await mlApi.getThresholds()
      const v = (t.data as any)?.anomaly_threshold
      if (t.success && typeof v === 'number') {
        setThreshold(v)
      }
    })()
  }, [])

  // ---------- helpers ----------
  const fetchStatus = async () => {
    try {
      const response = await mlApi.getStatus()
      if (response.success) {
        setStatus(response.data || null)
        setError(null)
      } else {
        setError(response.error || 'Failed to load ML status')
      }
    } catch (err) {
      console.error('Failed to fetch ML status:', err)
      setError('Failed to load ML status')
    } finally {
      setLoading(false)
    }
  }

  const trainModels = async () => {
    setTraining(true)
    setError(null)
    try {
      const response = await mlApi.train({ n_clusters: 3, contamination: 0.1 })
      if (!response.success) throw new Error(response.error || 'Training failed')

      setTimeout(async () => {
        await fetchStatus()
        const m = await mlApi.getMetrics()
        if (m.success && m.data) setMetrics(m.data)
        setTraining(false)
      }, 1500)
    } catch (err: any) {
      setError(err.message || 'Failed to train models')
      setTraining(false)
    }
  }

  const testThreatDetection = async () => {
    try {
      const testLog = {
        timestamp: new Date().toISOString(),
        source_ip: testIP,
        source_port: 8080,
        payload: testPayload,
        request_type: 'HTTP',
      }
      const response = await mlApi.getThreatScore(testLog)
      if (response.success) {
        setTestResult(response.data || null)
      } else {
        setError(response.error || 'Test failed')
      }
    } catch (err: any) {
      setError(err.message || 'Failed to test threat detection')
    }
  }

  // === Thresholds / Save / Load ===
  const commitThreshold = useCallback(async () => {
    try {
      const res = await mlApi.setThresholds({ anomaly_threshold: threshold })
      if (!res.success) throw new Error(res.error || 'Failed to set threshold')
      const m = await mlApi.getMetrics()
      if (m.success && m.data) setMetrics(m.data)
    } catch (e: any) {
      console.error(e)
      setError(e.message || 'Failed to set threshold')
    }
  }, [threshold])

  const saveModel = async () => {
    setSaving(true)
    try {
      const res = await mlApi.save()
      if (!res.success) throw new Error(res.error || 'Save failed')
    } catch (e: any) {
      setError(e.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  const loadModel = async () => {
    setLoadingModel(true)
    try {
      const res = await mlApi.load()
      if (!res.success) throw new Error(res.error || 'Load failed')

      await fetchStatus()
      const m = await mlApi.getMetrics()
      if (m.success && m.data) setMetrics(m.data)

      const t = await mlApi.getThresholds()
      if (t.success && typeof (t.data as any)?.anomaly_threshold === 'number') {
        setThreshold((t.data as any).anomaly_threshold)
      }
    } catch (e: any) {
      setError(e.message || 'Load failed')
    } finally {
      setLoadingModel(false)
    }
  }

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-500'
      case 'high': return 'text-orange-500'
      case 'medium': return 'text-yellow-500'
      case 'low': return 'text-green-500'
      default: return 'text-gray-500'
    }
  }

  const getThreatBg = (level: string) => {
    switch (level) {
      case 'critical': return 'bg-red-500/10 border-red-500/20'
      case 'high': return 'bg-orange-500/10 border-orange-500/20'
      case 'medium': return 'bg-yellow-500/10 border-yellow-500/20'
      case 'low': return 'bg-green-500/10 border-green-500/20'
      default: return 'bg-gray-500/10 border-gray-500/20'
    }
  }

  // Loading skeleton
  if (loading) {
    return (
      <ProtectedRoute>
      <div className="min-h-screen bg-dark-bg p-8">
        <div className="animate-pulse space-y-8">
          <div className="h-10 w-64 bg-muted/30 rounded"></div>
          <div className="grid grid-cols-4 gap-6">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-32 bg-muted/20 rounded-xl"></div>
            ))}
          </div>
          <div className="h-64 bg-muted/20 rounded-xl"></div>
        </div>
      </div>
      </ProtectedRoute>
    )
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="min-h-screen bg-dark-bg p-8"
    >
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
        className="mb-8"
      >
        <h1 className="text-4xl font-bold mb-2">
          <span className="gradient-cyber">Machine Learning Models</span>
        </h1>
        <p className="text-dark-text/70">
          AI-powered threat detection and behavioral analysis
        </p>
      </motion.div>

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        {/* Model Status */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          whileHover={{ scale: 1.02, y: -4 }}
          className={`p-6 rounded-xl border transition-all duration-300 hover:shadow-2xl ${
            status?.model_trained 
              ? 'bg-green-500/10 border-green-500/20 hover:shadow-green-500/20' 
              : 'bg-orange-500/10 border-orange-500/20 hover:shadow-orange-500/20'
          }`}
        >
          <div className="flex items-center justify-between mb-4">
            <motion.div
              animate={{ rotate: status?.model_trained ? 0 : [0, 10, -10, 0] }}
              transition={{ duration: 2, repeat: status?.model_trained ? 0 : Infinity, repeatDelay: 1 }}
            >
              <Brain className={`w-8 h-8 ${status?.model_trained ? 'text-green-500' : 'text-orange-500'}`} />
            </motion.div>
            <motion.span
              whileHover={{ scale: 1.05 }}
              className={`text-sm font-semibold px-3 py-1 rounded-full ${
                status?.model_trained ? 'bg-green-500/20 text-green-400' : 'bg-orange-500/20 text-orange-400'
              }`}
            >
              {status?.model_trained ? 'Trained' : 'Not Trained'}
            </motion.span>
          </div>
          <h3 className="text-sm text-dark-text/70 mb-1">Model Status</h3>
          <p className="text-2xl font-bold text-dark-text">
            {status?.model_trained ? 'Ready' : 'Needs Training'}
          </p>
        </motion.div>

        {/* Training Samples */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.2 }}
          whileHover={{ scale: 1.02, y: -4 }}
          className="p-6 bg-blue-500/10 border border-blue-500/20 rounded-xl hover:shadow-2xl hover:shadow-blue-500/20 transition-all duration-300"
        >
          <div className="flex items-center justify-between mb-4">
            <motion.div
              whileHover={{ rotate: 360 }}
              transition={{ duration: 0.5 }}
            >
              <Activity className="w-8 h-8 text-blue-500" />
            </motion.div>
          </div>
          <h3 className="text-sm text-dark-text/70 mb-1">Training Samples</h3>
          <p className="text-2xl font-bold text-dark-text text-blue-400">
            <CountUp end={status?.training_samples || 0} duration={2} />
          </p>
        </motion.div>

        {/* Feature Count */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.3 }}
          whileHover={{ scale: 1.02, y: -4 }}
          className="p-6 bg-purple-500/10 border border-purple-500/20 rounded-xl hover:shadow-2xl hover:shadow-purple-500/20 transition-all duration-300"
        >
          <div className="flex items-center justify-between mb-4">
            <motion.div
              whileHover={{ rotate: 360 }}
              transition={{ duration: 0.5 }}
            >
              <TrendingUp className="w-8 h-8 text-purple-500" />
            </motion.div>
          </div>
          <h3 className="text-sm text-dark-text/70 mb-1">Features</h3>
          <p className="text-2xl font-bold text-dark-text text-purple-400">
            <CountUp end={status?.feature_count || 0} duration={2} />
          </p>
        </motion.div>

        {/* Models Available */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.4 }}
          whileHover={{ scale: 1.02, y: -4 }}
          className="p-6 bg-cyan-500/10 border border-cyan-500/20 rounded-xl hover:shadow-2xl hover:shadow-cyan-500/20 transition-all duration-300"
        >
          <div className="flex items-center justify-between mb-4">
            <motion.div
              whileHover={{ scale: 1.2 }}
              transition={{ type: "spring", stiffness: 400 }}
            >
              <CheckCircle className="w-8 h-8 text-cyan-500" />
            </motion.div>
          </div>
          <h3 className="text-sm text-dark-text/70 mb-1">Models Ready</h3>
          <p className="text-2xl font-bold text-dark-text text-cyan-400">
            <CountUp end={(status?.anomaly_detector_available ? 1 : 0) + (status?.behavior_clusterer_available ? 1 : 0)} duration={2} />/2
          </p>
        </motion.div>
      </div>

      {/* Training Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.5 }}
        className="mb-8 p-6 bg-dark-card border border-dark-border rounded-xl hover:shadow-xl transition-shadow duration-300"
      >
        <h2 className="text-xl font-bold mb-4 text-dark-text">Model Training</h2>

        <div className="mb-4">
          <p className="text-sm text-dark-text/70 mb-2">
            Train ML models on security logs to detect anomalies and analyze behavioral patterns
          </p>
          {status?.training_date && (
            <p className="text-xs text-dark-text/50">
              Last trained: {new Date(status.training_date).toLocaleString()}
            </p>
          )}
        </div>

        <motion.button
          whileHover={{ scale: 1.01, y: -2 }}
          whileTap={{ scale: 0.99 }}
          onClick={trainModels}
          disabled={training}
          className={`w-full px-6 py-3 rounded-lg font-semibold transition-all flex items-center justify-center gap-2 ${
            training
              ? 'bg-gray-600 cursor-not-allowed'
              : 'bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 hover:shadow-lg hover:shadow-purple-500/20'
          }`}
        >
          {training ? (
            <>
              <RefreshCw className="w-5 h-5 animate-spin" />
              Training Models...
            </>
          ) : (
            <>
              <Zap className="w-5 h-5" />
              Train ML Models
            </>
          )}
        </motion.button>

        {/* Advanced controls row */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.6 }}
          className="mt-4 grid grid-cols-1 lg:grid-cols-3 gap-3"
        >
          {/* Threshold */}
          <motion.div
            whileHover={{ scale: 1.01 }}
            className="p-4 bg-dark-bg border border-dark-border rounded-lg hover:border-purple-500/50 transition-all duration-300"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-dark-text/70">Anomaly Threshold</span>
              <motion.span
                key={threshold}
                initial={{ scale: 1.2, color: '#a855f7' }}
                animate={{ scale: 1, color: '#fff' }}
                className="text-sm font-semibold text-dark-text"
              >
                <CountUp end={threshold} decimals={2} duration={0.5} />
              </motion.span>
            </div>
            <input
              type="range"
              min={minT}
              max={maxT}
              step={0.01}
              value={threshold}
              onChange={(e) => setThreshold(parseFloat(e.target.value))}
              onMouseUp={commitThreshold}
              onTouchEnd={commitThreshold}
              className="w-full accent-purple-500"
            />
          </motion.div>

          {/* Save / Load */}
          <motion.div
            whileHover={{ scale: 1.01 }}
            className="p-4 bg-dark-bg border border-dark-border rounded-lg flex gap-3"
          >
            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={saveModel}
              disabled={!status?.model_trained || saving}
              className={`flex-1 px-4 py-2 rounded-lg text-sm font-semibold transition-all duration-300
                ${(!status?.model_trained || saving)
                  ? 'bg-gray-600 cursor-not-allowed'
                  : 'bg-dark-card border border-dark-border hover:border-purple-500/50 hover:shadow-lg'}`}
            >
              {saving ? 'Saving…' : 'Save Model'}
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={loadModel}
              disabled={loadingModel}
              className={`flex-1 px-4 py-2 rounded-lg text-sm font-semibold transition-all duration-300
                ${loadingModel
                  ? 'bg-gray-600 cursor-not-allowed'
                  : 'bg-dark-card border border-dark-border hover:border-blue-500/50 hover:shadow-lg'}`}
            >
              {loadingModel ? 'Loading…' : 'Load Model'}
            </motion.button>
          </motion.div>

          {/* Metrics mini-card */}
          <motion.div
            whileHover={{ scale: 1.01 }}
            className="p-4 bg-dark-bg border border-dark-border rounded-lg hover:border-cyan-500/50 transition-all duration-300"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-dark-text/70">Model Metrics</span>
              <motion.span
                whileHover={{ scale: 1.05 }}
                className={`text-xs px-2 py-0.5 rounded-full ${
                  metrics?.trained ? 'bg-green-500/20 text-green-400' : 'bg-orange-500/20 text-orange-400'
                }`}
              >
                {metrics?.trained ? 'Trained' : 'Not trained'}
              </motion.span>
            </div>
            <div className="grid grid-cols-3 gap-2 text-xs text-dark-text/70">
              <div>
                <span className="block">Samples</span>
                <span className="font-semibold text-dark-text">
                  <CountUp end={metrics?.samples ?? 0} duration={1.5} />
                </span>
              </div>
              <div>
                <span className="block">Silhouette</span>
                <span className="font-semibold text-dark-text">
                  {metrics?.silhouette != null ? metrics.silhouette.toFixed(3) : '—'}
                </span>
              </div>
              <div>
                <span className="block">Labeled</span>
                <span className="font-semibold text-dark-text">
                  <CountUp end={metrics?.labeled_count ?? 0} duration={1.5} />
                </span>
              </div>
            </div>
          </motion.div>
        </motion.div>

        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400"
            >
              ⚠️ {error}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Test Console */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.7 }}
        className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8"
      >
        {/* Test Input */}
        <motion.div
          whileHover={{ scale: 1.01 }}
          className="p-6 bg-dark-card border border-dark-border rounded-xl hover:shadow-xl transition-all duration-300"
        >
          <h2 className="text-xl font-bold mb-4 text-dark-text">Test Threat Detection</h2>

          <div className="space-y-4 mb-4">
            <div>
              <label className="block text-sm text-dark-text/70 mb-2">Source IP</label>
              <input
                type="text"
                value={testIP}
                onChange={(e) => setTestIP(e.target.value)}
                className="w-full px-4 py-2 bg-dark-bg border border-dark-border rounded-lg text-dark-text focus:border-purple-500 focus:outline-none transition-all duration-300 focus:shadow-lg focus:shadow-purple-500/10"
                placeholder="192.168.1.100"
              />
            </div>

            <div>
              <label className="block text-sm text-dark-text/70 mb-2">Payload</label>
              <textarea
                value={testPayload}
                onChange={(e) => setTestPayload(e.target.value)}
                rows={3}
                className="w-full px-4 py-2 bg-dark-bg border border-dark-border rounded-lg text-dark-text focus:border-purple-500 focus:outline-none resize-none transition-all duration-300 focus:shadow-lg focus:shadow-purple-500/10"
                placeholder="GET /api/data"
              />
            </div>
          </div>

          <motion.button
            whileHover={{ scale: 1.02, y: -2 }}
            whileTap={{ scale: 0.98 }}
            onClick={testThreatDetection}
            disabled={!status?.model_trained}
            className={`w-full px-6 py-3 rounded-lg font-semibold transition-all duration-300 flex items-center justify-center gap-2 ${
              !status?.model_trained ? 'bg-gray-600 cursor-not-allowed' : 'bg-purple-600 hover:bg-purple-700 hover:shadow-lg hover:shadow-purple-500/30'
            }`}
          >
            <AlertTriangle className="w-5 h-5" />
            Analyze Threat
          </motion.button>

          {!status?.model_trained && (
            <p className="mt-2 text-xs text-orange-400 text-center">
              Train models first to enable threat detection
            </p>
          )}

          {/* Quick Test Buttons */}
          <div className="mt-4 space-y-2">
            <p className="text-xs text-dark-text/50 mb-2">Quick Tests:</p>
            <motion.button
              whileHover={{ scale: 1.02, x: 4 }}
              whileTap={{ scale: 0.98 }}
              onClick={() => {
                setTestIP('192.168.1.100')
                setTestPayload('GET /api/data?id=123')
              }}
              className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-xs text-dark-text hover:border-green-500/50 transition-all duration-300"
            >
              ✅ Normal Request
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.02, x: 4 }}
              whileTap={{ scale: 0.98 }}
              onClick={() => {
                setTestIP('10.0.0.1')
                setTestPayload("admin' OR '1'='1'; DROP TABLE users; <script>alert('XSS')</script>")
              }}
              className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-xs text-dark-text hover:border-red-500/50 transition-all duration-300"
            >
              ⚠️ SQL Injection + XSS
            </motion.button>
          </div>
        </motion.div>

        {/* Test Results */}
        <motion.div
          whileHover={{ scale: 1.01 }}
          className="p-6 bg-dark-card border border-dark-border rounded-xl hover:shadow-xl transition-all duration-300"
        >
          <h2 className="text-xl font-bold mb-4 text-dark-text">Analysis Results</h2>

          <AnimatePresence mode="wait">
            {testResult ? (
              <motion.div
                key="results"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ duration: 0.3 }}
                className="space-y-4"
              >
                {/* Threat Score */}
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`p-6 rounded-xl border ${getThreatBg(testResult.threat_level)} hover:shadow-lg transition-all duration-300`}
                >
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-bold text-dark-text">Threat Score</h3>
                    <motion.span
                      whileHover={{ scale: 1.05 }}
                      className={`text-sm font-semibold px-3 py-1 rounded-full bg-dark-bg`}
                    >
                      {testResult.threat_level.toUpperCase()}
                    </motion.span>
                  </div>
                  <div className="flex items-center gap-4">
                    <motion.div
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{ type: "spring", stiffness: 200, damping: 15 }}
                      className={`text-6xl font-bold ${getThreatColor(testResult.threat_level)}`}
                    >
                      <CountUp end={Math.round(testResult.threat_score)} duration={2} />
                    </motion.div>
                    <div className="flex-1">
                      <div className="h-4 bg-dark-bg rounded-full overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${testResult.threat_score}%` }}
                          transition={{ duration: 1, ease: "easeOut" }}
                          className={`h-full ${
                            testResult.threat_level === 'critical'
                              ? 'bg-red-500'
                              : testResult.threat_level === 'high'
                              ? 'bg-orange-500'
                              : testResult.threat_level === 'medium'
                              ? 'bg-yellow-500'
                              : 'bg-green-500'
                          }`}
                        />
                      </div>
                    </div>
                  </div>
                </motion.div>

                {/* Details */}
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.2 }}
                  className="space-y-3"
                >
                  {[
                    { label: 'Anomaly Detected', value: testResult.is_anomaly ? 'YES' : 'NO', color: testResult.is_anomaly ? 'text-red-400' : 'text-green-400' },
                    { label: 'Anomaly Score', value: testResult.anomaly_score.toFixed(3), color: 'text-dark-text' },
                    { label: 'Behavior Cluster', value: testResult.behavior_cluster, color: 'text-dark-text' },
                    { label: 'Confidence', value: `${(testResult.confidence * 100).toFixed(1)}%`, color: 'text-dark-text' },
                  ].map((item, index) => (
                    <motion.div
                      key={item.label}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.3 + index * 0.1 }}
                      whileHover={{ scale: 1.01, x: 4 }}
                      className="flex items-center justify-between p-3 bg-dark-bg rounded-lg transition-all duration-300"
                    >
                      <span className="text-sm text-dark-text/70">{item.label}</span>
                      <span className={`font-bold ${item.color}`}>{item.value}</span>
                    </motion.div>
                  ))}
                </motion.div>
              </motion.div>
            ) : (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="text-center py-12 text-dark-text/50"
              >
                <motion.div
                  animate={{ scale: [1, 1.1, 1], rotate: [0, 5, -5, 0] }}
                  transition={{ duration: 2, repeat: Infinity, repeatType: "reverse" }}
                >
                  <Brain className="w-16 h-16 mx-auto mb-4 opacity-50" />
                </motion.div>
                <p>No analysis results yet</p>
                <p className="text-sm">Test a log to see threat detection in action</p>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      </motion.div>

      {/* Features List */}
      {status?.features && status.features.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.8 }}
          className="p-6 bg-dark-card border border-dark-border rounded-xl hover:shadow-xl transition-shadow duration-300"
        >
          <h2 className="text-xl font-bold mb-4 text-dark-text">
            ML Features (<CountUp end={status.features.length} duration={1.5} />)
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {status.features.map((feature, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.2, delay: index * 0.02 }}
                whileHover={{ scale: 1.02, y: -2 }}
                className="p-3 bg-dark-bg border border-dark-border rounded-lg text-sm text-dark-text/70 hover:border-purple-500/50 transition-all duration-300"
              >
                {feature.replace(/_/g, ' ')}
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}
    </motion.div>
  )
}