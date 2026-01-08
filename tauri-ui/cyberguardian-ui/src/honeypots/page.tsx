'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import CountUp from 'react-countup'
import { RefreshCw, Activity, AlertTriangle, Shield, Globe, MapPin, Clock } from 'lucide-react'
import { honeypotApi } from '@/lib/api'
import HoneypotMap from '@/components/HoneypotMap'
import ProtectedRoute from '@/components/ProtectedRoute';

interface HoneypotStatus {
  name: string
  type: string
  port: number
  running: boolean
  attacks_logged: number
}

interface AttackLog {
  timestamp: string
  honeypot_type: string
  source_ip: string
  source_port: number
  attack_type: string
  payload: string
  country: string | null
  city: string | null
}

interface HoneypotStats {
  total_attacks: number
  active_honeypots: number
  attack_types: Record<string, number>
  top_countries: Record<string, number>
}

export default function HoneypotsPage() {
  const [honeypots, setHoneypots] = useState<HoneypotStatus[]>([])
  const [attacks, setAttacks] = useState<AttackLog[]>([])
  const [stats, setStats] = useState<HoneypotStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5000)
    return () => clearInterval(interval)
  }, [])

  const fetchData = async () => {
    try {
      const [statusRes, attacksRes, statsRes] = await Promise.all([
        honeypotApi.getStatus(),
        honeypotApi.getAttacks(20),
        honeypotApi.getStatistics()
      ])

      if (statusRes.success) setHoneypots(statusRes.data ?? [])
      if (attacksRes.success) setAttacks(attacksRes.data ?? [])
      if (statsRes.success) setStats(statsRes.data ?? null)    

      setLoading(false)
      setError(null)
    } catch (err) {
      console.error('Failed to fetch data:', err)
      setError('Failed to load honeypot data')
      setLoading(false)
    }
  }

  const startHoneypot = async (type: string) => {
    try {
      const response = await honeypotApi.start(type)
      if (response.success) {
        setTimeout(fetchData, 1000)
      }
    } catch (err) {
      console.error('Failed to start honeypot:', err)
    }
  }

  const stopHoneypot = async (type: string) => {
    try {
      const response = await honeypotApi.stop(type)
      if (response.success) {
        setTimeout(fetchData, 1000)
      }
    } catch (err) {
      console.error('Failed to stop honeypot:', err)
    }
  }

  const startAll = async () => {
    try {
      await honeypotApi.startAll()
      setTimeout(fetchData, 1000)
    } catch (err) {
      console.error('Failed to start all:', err)
    }
  }

  const stopAll = async () => {
    try {
      await honeypotApi.stopAll()
      setTimeout(fetchData, 1000)
    } catch (err) {
      console.error('Failed to stop all:', err)
    }
  }

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp)
    return date.toLocaleString()
  }

const getHoneypotColor = (type: string) => {
  const colors: Record<string, string> = {
    ssh: 'text-cyan-400',
    http: 'text-purple-400',
    ftp: 'text-green-400',
    telnet: 'text-orange-400',
    mysql: 'text-blue-400',
    redis: 'text-red-400',
    elasticsearch: 'text-yellow-400',
    mongodb: 'text-lime-400',
    postgresql: 'text-indigo-400'  // 🆕 ДОБАВИ ТОЗИ РЕД
  }
  return colors[type] || 'text-gray-400'
}

const getHoneypotBg = (type: string) => {
  const backgrounds: Record<string, string> = {
    ssh: 'bg-cyan-500/10 border-cyan-500/20',
    http: 'bg-purple-500/10 border-purple-500/20',
    ftp: 'bg-green-500/10 border-green-500/20',
    telnet: 'bg-orange-500/10 border-orange-500/20',
    mysql: 'bg-blue-500/10 border-blue-500/20',
    redis: 'bg-red-500/10 border-red-500/20',
    elasticsearch: 'bg-yellow-500/10 border-yellow-500/20',
    mongodb: 'bg-lime-500/10 border-lime-500/20',
    postgresql: 'bg-indigo-500/10 border-indigo-500/20'  // 🆕 ДОБАВИ
  }
  return backgrounds[type] || 'bg-gray-500/10 border-gray-500/20'
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
          <div className="grid grid-cols-2 gap-6">
            {[...Array(2)].map((_, i) => (
              <div key={i} className="h-48 bg-muted/20 rounded-xl"></div>
            ))}
          </div>
        </div>
      </div>
      </ProtectedRoute>
    )
  }

  return (
    <ProtectedRoute>
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
          <span className="gradient-cyber">Live Honeypots</span>
        </h1>
        <p className="text-dark-text/70">
          Real-time attack capture and analysis
        </p>
      </motion.div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        {/* Total Attacks */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          whileHover={{ scale: 1.02, y: -4 }}
          className="p-6 bg-red-500/10 border border-red-500/20 rounded-xl hover:shadow-2xl hover:shadow-red-500/20 transition-all duration-300"
        >
          <div className="flex items-center justify-between mb-4">
            <motion.div
              animate={{ 
                scale: stats?.total_attacks && stats.total_attacks > 0 ? [1, 1.2, 1] : 1,
                rotate: stats?.total_attacks && stats.total_attacks > 0 ? [0, 10, -10, 0] : 0
              }}
              transition={{ duration: 0.5, repeat: stats?.total_attacks && stats.total_attacks > 0 ? Infinity : 0, repeatDelay: 2 }}
            >
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </motion.div>
          </div>
          <h3 className="text-sm text-dark-text/70 mb-1">Total Attacks</h3>
          <p className="text-2xl font-bold text-red-500">
            <CountUp end={stats?.total_attacks || 0} duration={2} />
          </p>
        </motion.div>

        {/* Active Honeypots */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.2 }}
          whileHover={{ scale: 1.02, y: -4 }}
          className="p-6 bg-green-500/10 border border-green-500/20 rounded-xl hover:shadow-2xl hover:shadow-green-500/20 transition-all duration-300"
        >
          <div className="flex items-center justify-between mb-4">
            <motion.div
              animate={{ scale: [1, 1.1, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              <Activity className="w-8 h-8 text-green-500" />
            </motion.div>
          </div>
          <h3 className="text-sm text-dark-text/70 mb-1">Active Honeypots</h3>
          <p className="text-2xl font-bold text-green-500">
            <CountUp end={stats?.active_honeypots || 0} duration={2} />/9
          </p>
        </motion.div>

        {/* Attack Types */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.3 }}
          whileHover={{ scale: 1.02, y: -4 }}
          className="p-6 bg-orange-500/10 border border-orange-500/20 rounded-xl hover:shadow-2xl hover:shadow-orange-500/20 transition-all duration-300"
        >
          <div className="flex items-center justify-between mb-4">
            <motion.div
              whileHover={{ rotate: 360 }}
              transition={{ duration: 0.5 }}
            >
              <Shield className="w-8 h-8 text-orange-500" />
            </motion.div>
          </div>
          <h3 className="text-sm text-dark-text/70 mb-1">Attack Types</h3>
          <p className="text-2xl font-bold text-orange-500">
            <CountUp end={stats ? Object.keys(stats.attack_types).length : 0} duration={2} />
          </p>
        </motion.div>

        {/* Countries */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.4 }}
          whileHover={{ scale: 1.02, y: -4 }}
          className="p-6 bg-blue-500/10 border border-blue-500/20 rounded-xl hover:shadow-2xl hover:shadow-blue-500/20 transition-all duration-300"
        >
          <div className="flex items-center justify-between mb-4">
            <motion.div
              animate={{ rotate: [0, 360] }}
              transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
            >
              <Globe className="w-8 h-8 text-blue-500" />
            </motion.div>
          </div>
          <h3 className="text-sm text-dark-text/70 mb-1">Countries</h3>
          <p className="text-2xl font-bold text-blue-500">
            <CountUp end={stats ? Object.keys(stats.top_countries).length : 0} duration={2} />
          </p>
        </motion.div>
      </div>

      {/* Honeypot Controls */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        {honeypots.map((honeypot, index) => (
          <motion.div
            key={honeypot.type}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.5 + index * 0.1 }}
            whileHover={{ scale: 1.01, y: -4 }}
            className={`p-6 rounded-xl border transition-all duration-300 ${getHoneypotBg(honeypot.type)} hover:shadow-xl ${
  honeypot.type === 'ssh' ? 'hover:shadow-cyan-500/20' :
  honeypot.type === 'http' ? 'hover:shadow-purple-500/20' :
  honeypot.type === 'ftp' ? 'hover:shadow-green-500/20' :
  honeypot.type === 'telnet' ? 'hover:shadow-orange-500/20' :
  honeypot.type === 'mysql' ? 'hover:shadow-blue-500/20' :
  honeypot.type === 'redis' ? 'hover:shadow-red-500/20' :
  honeypot.type === 'elasticsearch' ? 'hover:shadow-yellow-500/20' :
  honeypot.type === 'mongodb' ? 'hover:shadow-lime-500/20' :
  honeypot.type === 'postgresql' ? 'hover:shadow-indigo-500/20' :  // 🆕 ДОБАВИ
  'hover:shadow-gray-500/20'
}`}
          >
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className={`text-xl font-bold ${getHoneypotColor(honeypot.type)}`}>
                  {honeypot.name}
                </h3>
                <p className="text-sm text-dark-text/70">Port: {honeypot.port}</p>
              </div>
              <motion.div
                animate={{ scale: honeypot.running ? [1, 1.1, 1] : 1 }}
                transition={{ duration: 2, repeat: honeypot.running ? Infinity : 0 }}
              >
                <span
                  className={`px-3 py-1 rounded-full text-sm font-semibold ${
                    honeypot.running
                      ? 'bg-green-500/20 text-green-400'
                      : 'bg-gray-500/20 text-gray-400'
                  }`}
                >
                  {honeypot.running ? '🟢 Running' : '🔴 Stopped'}
                </span>
              </motion.div>
            </div>

            <div className="mb-4">
              <p className="text-sm text-dark-text/70">Attacks Captured</p>
              <p className="text-3xl font-bold text-dark-text">
                <CountUp end={honeypot.attacks_logged} duration={2} />
              </p>
            </div>

            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={() =>
                honeypot.running ? stopHoneypot(honeypot.type) : startHoneypot(honeypot.type)
              }
              className={`w-full px-4 py-2 rounded-lg font-semibold transition-all duration-300 ${
                honeypot.running
                  ? 'bg-red-600 hover:bg-red-700 hover:shadow-lg hover:shadow-red-500/30'
                  : 'bg-green-600 hover:bg-green-700 hover:shadow-lg hover:shadow-green-500/30'
              }`}
            >
              {honeypot.running ? 'Stop' : 'Start'} Honeypot
            </motion.button>
          </motion.div>
        ))}
      </div>

      {/* Control All */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.7 }}
        className="flex gap-4 mb-8"
      >
        <motion.button
          whileHover={{ scale: 1.02, y: -2 }}
          whileTap={{ scale: 0.98 }}
          onClick={startAll}
          className="flex-1 px-6 py-3 bg-green-600 hover:bg-green-700 rounded-lg font-semibold transition-all duration-300 hover:shadow-lg hover:shadow-green-500/30"
        >
          🚀 Start All Honeypots
        </motion.button>
        <motion.button
          whileHover={{ scale: 1.02, y: -2 }}
          whileTap={{ scale: 0.98 }}
          onClick={stopAll}
          className="flex-1 px-6 py-3 bg-red-600 hover:bg-red-700 rounded-lg font-semibold transition-all duration-300 hover:shadow-lg hover:shadow-red-500/30"
        >
          🛑 Stop All Honeypots
        </motion.button>
        <motion.button
          whileHover={{ scale: 1.02, y: -2 }}
          whileTap={{ scale: 0.98 }}
          onClick={fetchData}
          className="px-6 py-3 bg-purple-600 hover:bg-purple-700 rounded-lg font-semibold transition-all duration-300 flex items-center gap-2 hover:shadow-lg hover:shadow-purple-500/30"
        >
          <RefreshCw className="w-5 h-5" />
          Refresh
        </motion.button>
      </motion.div>

      {/* Geo Map */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.8 }}
        className="mb-8"
      >
        <h2 className="text-2xl font-bold mb-4 text-dark-text">
          Attack Origins Map
        </h2>
        <motion.div
          whileHover={{ scale: 1.005 }}
          className="overflow-hidden rounded-xl border border-dark-border hover:shadow-xl transition-all duration-300"
        >
          <HoneypotMap />
        </motion.div>
      </motion.div>

      {/* Recent Attacks */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.9 }}
        className="mb-8"
      >
        <h2 className="text-2xl font-bold mb-4 text-dark-text">
          Recent Attacks (<CountUp end={attacks.length} duration={1} />)
        </h2>

        <AnimatePresence mode="wait">
          {attacks.length === 0 ? (
            <motion.div
              key="no-attacks"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="p-12 bg-dark-card border border-dark-border rounded-xl text-center"
            >
              <motion.div
                animate={{ scale: [1, 1.1, 1], rotate: [0, 5, -5, 0] }}
                transition={{ duration: 2, repeat: Infinity, repeatType: "reverse" }}
              >
                <Shield className="w-16 h-16 mx-auto mb-4 text-dark-text/30" />
              </motion.div>
              <p className="text-dark-text/50">No attacks captured yet</p>
              <p className="text-sm text-dark-text/30">Start honeypots to begin capturing attacks</p>
            </motion.div>
          ) : (
            <motion.div
              key="attacks"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="space-y-3"
            >
              {attacks.map((attack, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: index * 0.05 }}
                  whileHover={{ scale: 1.01, x: 4 }}
                  className="p-4 bg-dark-card border border-dark-border rounded-lg hover:border-purple-500/50 transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/10"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <motion.span
                          whileHover={{ scale: 1.05 }}
className={`px-3 py-1 rounded-full text-xs font-semibold ${
  attack.honeypot_type === 'ssh' ? 'bg-cyan-500/20 text-cyan-400' :
  attack.honeypot_type === 'http' ? 'bg-purple-500/20 text-purple-400' :
  attack.honeypot_type === 'ftp' ? 'bg-green-500/20 text-green-400' :
  attack.honeypot_type === 'telnet' ? 'bg-orange-500/20 text-orange-400' :
  attack.honeypot_type === 'mysql' ? 'bg-blue-500/20 text-blue-400' :
  attack.honeypot_type === 'redis' ? 'bg-red-500/20 text-red-400' :
  attack.honeypot_type === 'elasticsearch' ? 'bg-yellow-500/20 text-yellow-400' :
  attack.honeypot_type === 'mongodb' ? 'bg-lime-500/20 text-lime-400' :
  attack.honeypot_type === 'postgresql' ? 'bg-indigo-500/20 text-indigo-400' :  // 🆕 ДОБАВИ
  'bg-gray-500/20 text-gray-400'
}`}
                        >
                          {attack.honeypot_type.toUpperCase()}
                        </motion.span>
                        <h3 className="font-bold text-dark-text">{attack.attack_type}</h3>
                      </div>

                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm text-dark-text/70">
                        <div className="flex items-center gap-2">
                          <Globe className="w-4 h-4" />
                          {attack.source_ip}
                        </div>
                        {attack.country && (
                          <div className="flex items-center gap-2">
                            <MapPin className="w-4 h-4" />
                            {attack.city}, {attack.country}
                          </div>
                        )}
                        <div className="flex items-center gap-2">
                          <Clock className="w-4 h-4" />
                          {formatTimestamp(attack.timestamp)}
                        </div>
                      </div>

                      {attack.payload && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          transition={{ delay: 0.2 }}
                          className="mt-3 p-3 bg-dark-bg rounded-lg"
                        >
                          <p className="text-xs text-dark-text/50 mb-1">Payload:</p>
                          <pre className="text-xs text-dark-text/70 overflow-x-auto whitespace-pre-wrap break-all">
                            {attack.payload.substring(0, 200)}
                            {attack.payload.length > 200 && '...'}
                          </pre>
                        </motion.div>
                      )}
                    </div>
                  </div>
                </motion.div>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Attack Statistics */}
      {stats && Object.keys(stats.attack_types).length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 1 }}
          className="grid grid-cols-1 md:grid-cols-2 gap-6"
        >
          {/* Attack Types */}
          <motion.div
            whileHover={{ scale: 1.005, y: -4 }}
            className="p-6 bg-dark-card border border-dark-border rounded-xl hover:shadow-xl transition-all duration-300"
          >
            <h3 className="text-xl font-bold mb-4 text-dark-text">Attack Types</h3>
            <div className="space-y-3">
              {Object.entries(stats.attack_types)
                .sort(([, a], [, b]) => b - a)
                .map(([type, count], index) => (
                  <motion.div
                    key={type}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.3, delay: index * 0.05 }}
                    whileHover={{ scale: 1.02, x: 4 }}
                    className="flex items-center justify-between p-2 rounded-lg hover:bg-dark-bg transition-all"
                  >
                    <span className="text-dark-text/70">{type}</span>
                    <span className="font-bold text-dark-text">
                      <CountUp end={count} duration={1.5} />
                    </span>
                  </motion.div>
                ))}
            </div>
          </motion.div>

          {/* Top Countries */}
          <motion.div
            whileHover={{ scale: 1.005, y: -4 }}
            className="p-6 bg-dark-card border border-dark-border rounded-xl hover:shadow-xl transition-all duration-300"
          >
            <h3 className="text-xl font-bold mb-4 text-dark-text">Top Countries</h3>
            <div className="space-y-3">
              {Object.entries(stats.top_countries)
                .sort(([, a], [, b]) => b - a)
                .slice(0, 10)
                .map(([country, count], index) => (
                  <motion.div
                    key={country}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.3, delay: index * 0.05 }}
                    whileHover={{ scale: 1.02, x: 4 }}
                    className="flex items-center justify-between p-2 rounded-lg hover:bg-dark-bg transition-all"
                  >
                    <span className="text-dark-text/70">{country}</span>
                    <span className="font-bold text-dark-text">
                      <CountUp end={count} duration={1.5} />
                    </span>
                  </motion.div>
                ))}
            </div>
          </motion.div>
        </motion.div>
      )}
    </motion.div>
    </ProtectedRoute>
  )
}