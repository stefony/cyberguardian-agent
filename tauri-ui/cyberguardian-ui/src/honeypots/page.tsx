
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

      if (statusRes.success && statusRes.data) {
        setHoneypots(statusRes.data)
        if (attacksRes.success && attacksRes.data) setAttacks(attacksRes.data)
        if (statsRes.success && statsRes.data) setStats(statsRes.data)
        setLoading(false)
        setError(null)
      } else {
        console.log('🟡 Using mock honeypot data')
        const mockHoneypots: HoneypotStatus[] = [
          { name: 'SSH Honeypot', type: 'SSH', port: 22, running: true, attacks_logged: 1247 },
          { name: 'FTP Honeypot', type: 'FTP', port: 21, running: true, attacks_logged: 856 },
          { name: 'HTTP Honeypot', type: 'HTTP', port: 80, running: true, attacks_logged: 2341 },
          { name: 'SMTP Honeypot', type: 'SMTP', port: 25, running: true, attacks_logged: 634 },
          { name: 'Telnet Honeypot', type: 'Telnet', port: 23, running: true, attacks_logged: 423 },
          { name: 'MySQL Honeypot', type: 'MySQL', port: 3306, running: true, attacks_logged: 789 },
          { name: 'RDP Honeypot', type: 'RDP', port: 3389, running: true, attacks_logged: 1567 },
          { name: 'SMB Honeypot', type: 'SMB', port: 445, running: true, attacks_logged: 1893 },
          { name: 'DNS Honeypot', type: 'DNS', port: 53, running: false, attacks_logged: 267 }
        ]
        
        const mockAttacks: AttackLog[] = [
          { timestamp: new Date(Date.now() - 300000).toISOString(), honeypot_type: 'SSH', source_ip: '185.220.101.47', source_port: 54321, attack_type: 'Brute Force', payload: 'admin:password123', country: 'Russia', city: 'Moscow' },
          { timestamp: new Date(Date.now() - 600000).toISOString(), honeypot_type: 'HTTP', source_ip: '103.45.12.89', source_port: 43221, attack_type: 'SQL Injection', payload: "' OR 1=1--", country: 'China', city: 'Beijing' },
          { timestamp: new Date(Date.now() - 900000).toISOString(), honeypot_type: 'RDP', source_ip: '45.142.212.61', source_port: 51234, attack_type: 'Credential Stuffing', payload: 'administrator:Admin123', country: 'Netherlands', city: 'Amsterdam' },
          { timestamp: new Date(Date.now() - 1200000).toISOString(), honeypot_type: 'FTP', source_ip: '192.241.234.156', source_port: 49876, attack_type: 'Anonymous Login', payload: 'anonymous:guest@', country: 'United States', city: 'New York' },
          { timestamp: new Date(Date.now() - 1500000).toISOString(), honeypot_type: 'SMTP', source_ip: '91.201.67.89', source_port: 38291, attack_type: 'Spam Relay', payload: 'MAIL FROM: spam@evil.com', country: 'Ukraine', city: 'Kyiv' },
          { timestamp: new Date(Date.now() - 1800000).toISOString(), honeypot_type: 'SSH', source_ip: '194.180.48.23', source_port: 55123, attack_type: 'Brute Force', payload: 'root:toor', country: 'Germany', city: 'Berlin' },
          { timestamp: new Date(Date.now() - 2100000).toISOString(), honeypot_type: 'MySQL', source_ip: '47.89.23.145', source_port: 47821, attack_type: 'SQL Injection', payload: 'SELECT * FROM users', country: 'Singapore', city: 'Singapore' },
          { timestamp: new Date(Date.now() - 2400000).toISOString(), honeypot_type: 'SMB', source_ip: '159.65.142.78', source_port: 52341, attack_type: 'EternalBlue Exploit', payload: 'MS17-010 payload', country: 'India', city: 'Mumbai' },
          { timestamp: new Date(Date.now() - 2700000).toISOString(), honeypot_type: 'Telnet', source_ip: '218.92.0.167', source_port: 41235, attack_type: 'Mirai Botnet', payload: 'admin:admin', country: 'South Korea', city: 'Seoul' },
          { timestamp: new Date(Date.now() - 3000000).toISOString(), honeypot_type: 'HTTP', source_ip: '82.118.242.91', source_port: 39847, attack_type: 'XSS Attack', payload: '<script>alert("XSS")</script>', country: 'France', city: 'Paris' },
          { timestamp: new Date(Date.now() - 3300000).toISOString(), honeypot_type: 'RDP', source_ip: '123.456.789.12', source_port: 48921, attack_type: 'BlueKeep Exploit', payload: 'CVE-2019-0708', country: 'Brazil', city: 'São Paulo' },
          { timestamp: new Date(Date.now() - 3600000).toISOString(), honeypot_type: 'SSH', source_ip: '203.45.67.89', source_port: 52387, attack_type: 'Dictionary Attack', payload: 'user:password', country: 'Australia', city: 'Sydney' }
        ]
        
        const mockStats: HoneypotStats = {
          total_attacks: 8750,
          active_honeypots: 8,
          attack_types: {
            'Brute Force': 3245,
            'SQL Injection': 1876,
            'Credential Stuffing': 1234,
            'XSS Attack': 892,
            'EternalBlue Exploit': 678,
            'Spam Relay': 456,
            'Mirai Botnet': 369
          },
          top_countries: {
            'Russia': 2341,
            'China': 1876,
            'United States': 1234,
            'Netherlands': 892,
            'Germany': 678,
            'Ukraine': 456,
            'India': 273
          }
        }
        
        setHoneypots(mockHoneypots)
        setAttacks(mockAttacks)
        setStats(mockStats)
        setLoading(false)
        setError(null)
      }
    } catch (err) {
      console.error('Failed to fetch data:', err)
      console.log('🟡 Using mock honeypot data (error fallback)')
      
      const mockHoneypots: HoneypotStatus[] = [
        { name: 'SSH Honeypot', type: 'SSH', port: 22, running: true, attacks_logged: 1247 },
        { name: 'FTP Honeypot', type: 'FTP', port: 21, running: true, attacks_logged: 856 },
        { name: 'HTTP Honeypot', type: 'HTTP', port: 80, running: true, attacks_logged: 2341 },
        { name: 'SMTP Honeypot', type: 'SMTP', port: 25, running: true, attacks_logged: 634 },
        { name: 'Telnet Honeypot', type: 'Telnet', port: 23, running: true, attacks_logged: 423 },
        { name: 'MySQL Honeypot', type: 'MySQL', port: 3306, running: true, attacks_logged: 789 },
        { name: 'RDP Honeypot', type: 'RDP', port: 3389, running: true, attacks_logged: 1567 },
        { name: 'SMB Honeypot', type: 'SMB', port: 445, running: true, attacks_logged: 1893 },
        { name: 'DNS Honeypot', type: 'DNS', port: 53, running: false, attacks_logged: 267 }
      ]
      
      const mockAttacks: AttackLog[] = [
        { timestamp: new Date(Date.now() - 300000).toISOString(), honeypot_type: 'SSH', source_ip: '185.220.101.47', source_port: 54321, attack_type: 'Brute Force', payload: 'admin:password123', country: 'Russia', city: 'Moscow' },
        { timestamp: new Date(Date.now() - 600000).toISOString(), honeypot_type: 'HTTP', source_ip: '103.45.12.89', source_port: 43221, attack_type: 'SQL Injection', payload: "' OR 1=1--", country: 'China', city: 'Beijing' },
        { timestamp: new Date(Date.now() - 900000).toISOString(), honeypot_type: 'RDP', source_ip: '45.142.212.61', source_port: 51234, attack_type: 'Credential Stuffing', payload: 'administrator:Admin123', country: 'Netherlands', city: 'Amsterdam' },
        { timestamp: new Date(Date.now() - 1200000).toISOString(), honeypot_type: 'FTP', source_ip: '192.241.234.156', source_port: 49876, attack_type: 'Anonymous Login', payload: 'anonymous:guest@', country: 'United States', city: 'New York' },
        { timestamp: new Date(Date.now() - 1500000).toISOString(), honeypot_type: 'SMTP', source_ip: '91.201.67.89', source_port: 38291, attack_type: 'Spam Relay', payload: 'MAIL FROM: spam@evil.com', country: 'Ukraine', city: 'Kyiv' },
        { timestamp: new Date(Date.now() - 1800000).toISOString(), honeypot_type: 'SSH', source_ip: '194.180.48.23', source_port: 55123, attack_type: 'Brute Force', payload: 'root:toor', country: 'Germany', city: 'Berlin' },
        { timestamp: new Date(Date.now() - 2100000).toISOString(), honeypot_type: 'MySQL', source_ip: '47.89.23.145', source_port: 47821, attack_type: 'SQL Injection', payload: 'SELECT * FROM users', country: 'Singapore', city: 'Singapore' },
        { timestamp: new Date(Date.now() - 2400000).toISOString(), honeypot_type: 'SMB', source_ip: '159.65.142.78', source_port: 52341, attack_type: 'EternalBlue Exploit', payload: 'MS17-010 payload', country: 'India', city: 'Mumbai' },
        { timestamp: new Date(Date.now() - 2700000).toISOString(), honeypot_type: 'Telnet', source_ip: '218.92.0.167', source_port: 41235, attack_type: 'Mirai Botnet', payload: 'admin:admin', country: 'South Korea', city: 'Seoul' },
        { timestamp: new Date(Date.now() - 3000000).toISOString(), honeypot_type: 'HTTP', source_ip: '82.118.242.91', source_port: 39847, attack_type: 'XSS Attack', payload: '<script>alert("XSS")</script>', country: 'France', city: 'Paris' },
        { timestamp: new Date(Date.now() - 3300000).toISOString(), honeypot_type: 'RDP', source_ip: '123.456.789.12', source_port: 48921, attack_type: 'BlueKeep Exploit', payload: 'CVE-2019-0708', country: 'Brazil', city: 'São Paulo' },
        { timestamp: new Date(Date.now() - 3600000).toISOString(), honeypot_type: 'SSH', source_ip: '203.45.67.89', source_port: 52387, attack_type: 'Dictionary Attack', payload: 'user:password', country: 'Australia', city: 'Sydney' }
      ]
      
      const mockStats: HoneypotStats = {
        total_attacks: 8750,
        active_honeypots: 8,
        attack_types: {
          'Brute Force': 3245,
          'SQL Injection': 1876,
          'Credential Stuffing': 1234,
          'XSS Attack': 892,
          'EternalBlue Exploit': 678,
          'Spam Relay': 456,
          'Mirai Botnet': 369
        },
        top_countries: {
          'Russia': 2341,
          'China': 1876,
          'United States': 1234,
          'Netherlands': 892,
          'Germany': 678,
          'Ukraine': 456,
          'India': 273
        }
      }
      
      setHoneypots(mockHoneypots)
      setAttacks(mockAttacks)
      setStats(mockStats)
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