/**
 * CyberGuardian XDR — Process Tree Page
 * Real-time hierarchical process visualization with anomaly detection
 * MITRE ATT&CK annotated · enterprise-grade · CrowdStrike/SentinelOne quality
 */

import { useState, useEffect, useCallback, useRef } from 'react'
 import { invoke } from '@tauri-apps/api/core'
import { cn } from '@/lib/utils'
import {
  GitBranch,
  ChevronRight,
  ChevronDown,
  RefreshCw,
  AlertTriangle,
  Shield,
  Activity,
  Search,
  Filter,
  Cpu,
  MemoryStick,
  User,
  Terminal,
  Clock,
  XCircle,
  CheckCircle,
  Info,
  Zap,
} from 'lucide-react'

// ─── Types ───────────────────────────────────────────────────────────────────

interface ProcessNode {
  pid: number
  name: string
  ppid: number
  username: string
  cpu_percent: number
  memory_mb: number
  exe_path: string
  status: string
  suspicious: boolean
  anomaly_type: string
  mitre_technique: string
  severity: string
  children: ProcessNode[]
}

interface TreeResponse {
  success: boolean
  total_roots: number
  anomalies_detected: number
  tree: ProcessNode[]
}

// ─── MITRE badge config ───────────────────────────────────────────────────────

const MITRE_COLORS: Record<string, string> = {
  'T1047':     'bg-red-900/60 text-red-300 border-red-700',
  'T1059':     'bg-orange-900/60 text-orange-300 border-orange-700',
  'T1059.001': 'bg-orange-900/60 text-orange-300 border-orange-700',
  'T1059.005': 'bg-orange-900/60 text-orange-300 border-orange-700',
  'T1055':     'bg-purple-900/60 text-purple-300 border-purple-700',
  'T1566.001': 'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  'T1218.005': 'bg-pink-900/60 text-pink-300 border-pink-700',
  'T1218.010': 'bg-pink-900/60 text-pink-300 border-pink-700',
  'T1021.006': 'bg-cyan-900/60 text-cyan-300 border-cyan-700',
}

const SEVERITY_CONFIG = {
  critical: { bar: 'bg-red-500',    text: 'text-red-400',    badge: 'bg-red-900/50 text-red-300 border-red-600' },
  high:     { bar: 'bg-orange-500', text: 'text-orange-400', badge: 'bg-orange-900/50 text-orange-300 border-orange-600' },
  medium:   { bar: 'bg-yellow-500', text: 'text-yellow-400', badge: 'bg-yellow-900/50 text-yellow-300 border-yellow-600' },
  low:      { bar: 'bg-blue-500',   text: 'text-blue-400',   badge: 'bg-blue-900/50 text-blue-300 border-blue-600' },
}

// ─── Process Row Component ────────────────────────────────────────────────────

interface ProcessRowProps {
  node: ProcessNode
  depth: number
  searchQuery: string
  showSuspiciousOnly: boolean
}

function ProcessRow({ node, depth, searchQuery, showSuspiciousOnly }: ProcessRowProps) {
 const [expanded, setExpanded] = useState(depth < 2)
  const hasChildren = node.children.length > 0

  const matchesSearch = !searchQuery ||
    node.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    node.pid.toString().includes(searchQuery) ||
    node.username.toLowerCase().includes(searchQuery.toLowerCase())

  if (!matchesSearch && !hasChildren) return null
  if (showSuspiciousOnly && !node.suspicious && !node.children.some(c => c.suspicious)) return null

  const sevCfg = node.severity ? SEVERITY_CONFIG[node.severity as keyof typeof SEVERITY_CONFIG] : null
  const mitreCls = node.mitre_technique ? MITRE_COLORS[node.mitre_technique] ?? 'bg-gray-800 text-gray-300 border-gray-600' : ''

  const cpuBarWidth = Math.min(node.cpu_percent * 5, 100)
  const memBarWidth = Math.min((node.memory_mb / 500) * 100, 100)

  return (
    <>
      {/* Row */}
      <div
        className={cn(
          'group grid items-center border-b border-dark-border/40 transition-colors duration-150',
          'hover:bg-white/[0.02]',
          node.suspicious && 'bg-red-950/20 hover:bg-red-950/30 border-b-red-900/30',
          'cursor-default select-none',
        )}
        style={{ gridTemplateColumns: '1fr 80px 120px 100px 140px 180px 120px' }}
      >
        {/* Process Name */}
        <div className="flex items-center gap-1.5 px-3 py-2.5 min-w-0" style={{ paddingLeft: `${12 + depth * 20}px` }}>
          {/* Tree connector */}
          {depth > 0 && (
            <span className="shrink-0 text-dark-border/60 font-mono text-xs mr-0.5">└─</span>
          )}

          {/* Expand/collapse */}
          <button
            onClick={() => setExpanded(v => !v)}
            className={cn(
              'shrink-0 flex items-center justify-center w-4 h-4 rounded transition-colors',
              hasChildren ? 'text-muted-foreground hover:text-foreground' : 'invisible'
            )}
          >
            {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
          </button>

          {/* Suspicious indicator */}
          {node.suspicious ? (
            <AlertTriangle className="shrink-0 w-3.5 h-3.5 text-red-400 animate-pulse" />
          ) : (
            <div className="shrink-0 w-3.5 h-3.5 rounded-full bg-cyber-green/20 flex items-center justify-center">
              <div className="w-1.5 h-1.5 rounded-full bg-cyber-green/60" />
            </div>
          )}

          {/* Process name */}
          <span className={cn(
            'truncate text-sm font-mono font-medium',
            node.suspicious ? 'text-red-300' : 'text-foreground'
          )}>
            {node.name}
          </span>

          {/* MITRE badge */}
          {node.mitre_technique && (
            <span className={cn(
              'shrink-0 text-[10px] font-bold px-1.5 py-0.5 rounded border font-mono',
              mitreCls
            )}>
              {node.mitre_technique}
            </span>
          )}
        </div>

        {/* PID */}
        <div className="px-2 py-2.5 text-xs font-mono text-muted-foreground text-right">
          {node.pid}
        </div>

        {/* CPU */}
        <div className="px-3 py-2.5">
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 bg-dark-bg rounded-full overflow-hidden">
              <div
                className={cn('h-full rounded-full transition-all', node.cpu_percent > 50 ? 'bg-red-500' : node.cpu_percent > 20 ? 'bg-yellow-500' : 'bg-cyber-green')}
                style={{ width: `${cpuBarWidth}%` }}
              />
            </div>
            <span className="text-xs font-mono text-muted-foreground w-10 text-right shrink-0">
              {node.cpu_percent.toFixed(1)}%
            </span>
          </div>
        </div>

        {/* Memory */}
        <div className="px-3 py-2.5">
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 bg-dark-bg rounded-full overflow-hidden">
              <div
                className="h-full rounded-full bg-cyber-blue transition-all"
                style={{ width: `${memBarWidth}%` }}
              />
            </div>
            <span className="text-xs font-mono text-muted-foreground w-14 text-right shrink-0">
              {node.memory_mb.toFixed(0)} MB
            </span>
          </div>
        </div>

        {/* Username */}
        <div className="px-3 py-2.5">
          <span className="text-xs text-muted-foreground font-mono truncate block">{node.username}</span>
        </div>

        {/* Anomaly */}
        <div className="px-3 py-2.5">
          {node.anomaly_type ? (
            <span className="text-xs text-red-400 font-mono truncate block" title={node.anomaly_type}>
              {node.anomaly_type}
            </span>
          ) : (
            <span className="text-xs text-dark-border font-mono">—</span>
          )}
        </div>

        {/* Status / Severity */}
        <div className="px-3 py-2.5 flex items-center gap-2">
          {node.suspicious && sevCfg ? (
            <span className={cn('text-[10px] font-bold uppercase px-2 py-0.5 rounded border', sevCfg.badge)}>
              {node.severity}
            </span>
          ) : (
            <span className="text-[10px] font-medium uppercase px-2 py-0.5 rounded border bg-cyber-green/10 text-cyber-green border-cyber-green/30">
              {node.status || 'running'}
            </span>
          )}
        </div>
      </div>

      {/* Children */}
      {expanded && hasChildren && node.children.map(child => (
        <ProcessRow
          key={`${child.pid}-${child.name}`}
          node={child}
          depth={depth + 1}
          searchQuery={searchQuery}
          showSuspiciousOnly={showSuspiciousOnly}
        />
      ))}
    </>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ProcessTreePage() {
  const token = localStorage.getItem('access_token') || localStorage.getItem('token') || ''
  const [tree, setTree] = useState<ProcessNode[]>([])
  const [anomalyCount, setAnomalyCount] = useState(0)
  const [totalRoots, setTotalRoots] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080'

  const fetchTree = useCallback(async () => {
    try {
      setError(null)
      const res = await fetch(`${API_BASE}/api/process-monitor/tree`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data: TreeResponse = await res.json()
      if (data.success) {
        setTree(data.tree)
        setAnomalyCount(data.anomalies_detected)
        setTotalRoots(data.total_roots)
        setLastRefresh(new Date())
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to fetch process tree')
    } finally {
      setLoading(false)
    }
  }, [token, API_BASE])

  // Initial load
  useEffect(() => { fetchTree() }, [fetchTree])

  // Trigger Desktop Agent upload при зареждане
useEffect(() => {
  const triggerUpload = async () => {
    try {
      const token = localStorage.getItem('access_token') || localStorage.getItem('token') || ''
      await invoke('start_background_upload', { apiToken: token })
      console.log('✅ Background upload triggered')
      // Изчакай 2 сек за да се качат процесите, после refresh
      setTimeout(() => fetchTree(), 2000)
    } catch (e) {
      console.warn('⚠️ Could not trigger background upload (non-Tauri env):', e)
    }
  }
  triggerUpload()
}, []) 

  // Auto-refresh every 30s
  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(fetchTree, 30_000)
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current) }
  }, [autoRefresh, fetchTree])

  // Count total processes in tree
  const countNodes = (nodes: ProcessNode[]): number =>
    nodes.reduce((acc, n) => acc + 1 + countNodes(n.children), 0)

  const totalProcesses = countNodes(tree)
 

const flattenTree = (nodes: ProcessNode[]): ProcessNode[] =>
  nodes.reduce((acc, n) => [...acc, n, ...flattenTree(n.children)], [] as ProcessNode[])

return (
    <div className="flex flex-col h-full min-h-screen bg-dark-bg text-foreground">

      {/* ── Header ── */}
      <div className="border-b border-dark-border bg-dark-surface px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-purple-600 to-cyber-blue">
              <GitBranch className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-foreground">Process Tree</h1>
              <p className="text-xs text-muted-foreground">
                Live process hierarchy · Anomaly detection · MITRE ATT&CK mapping
              </p>
            </div>
          </div>

          {/* Stats pills */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 rounded-lg border border-dark-border bg-dark-bg px-3 py-1.5">
              <Activity className="h-3.5 w-3.5 text-cyber-green" />
              <span className="text-xs font-medium text-cyber-green">{totalProcesses} Processes</span>
            </div>
            {anomalyCount > 0 && (
              <div className="flex items-center gap-2 rounded-lg border border-red-700 bg-red-950/40 px-3 py-1.5 animate-pulse">
                <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
                <span className="text-xs font-bold text-red-400">{anomalyCount} Anomalies</span>
              </div>
            )}
            {anomalyCount === 0 && !loading && (
              <div className="flex items-center gap-2 rounded-lg border border-cyber-green/40 bg-cyber-green/10 px-3 py-1.5">
                <Shield className="h-3.5 w-3.5 text-cyber-green" />
                <span className="text-xs font-medium text-cyber-green">All Clear</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Toolbar ── */}
      <div className="flex items-center gap-3 border-b border-dark-border bg-dark-surface/60 px-6 py-3">
        {/* Search */}
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search process, PID, user..."
            value={searchQuery}
           onChange={e => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-dark-border bg-dark-bg pl-9 pr-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-purple-500/50"
          />
        </div>

        {/* Filter suspicious */}
        <button
          onClick={() => setShowSuspiciousOnly(v => !v)}
          className={cn(
            'flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors',
            showSuspiciousOnly
              ? 'border-red-600 bg-red-950/40 text-red-300'
              : 'border-dark-border bg-dark-bg text-muted-foreground hover:text-foreground'
          )}
        >
          <Filter className="h-3.5 w-3.5" />
          {showSuspiciousOnly ? 'Suspicious Only' : 'All Processes'}
        </button>

        {/* Spacer */}
        <div className="flex-1" />

        {/* Last refresh */}
        {lastRefresh && (
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Clock className="h-3 w-3" />
            {lastRefresh.toLocaleTimeString()}
          </div>
        )}

        {/* Auto-refresh toggle */}
        <button
          onClick={() => setAutoRefresh(v => !v)}
          className={cn(
            'flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors',
            autoRefresh
              ? 'border-cyber-green/40 bg-cyber-green/10 text-cyber-green'
              : 'border-dark-border bg-dark-bg text-muted-foreground'
          )}
        >
          <Zap className="h-3.5 w-3.5" />
          Auto 30s
        </button>

        {/* Manual refresh */}
        <button
          onClick={fetchTree}
          disabled={loading}
          className="flex items-center gap-2 rounded-lg border border-dark-border bg-dark-bg px-3 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground hover:border-purple-500/50 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {/* ── Table Header ── */}
      <div
        className="grid border-b border-dark-border bg-dark-surface/80 px-0 sticky top-0 z-10"
        style={{ gridTemplateColumns: '1fr 80px 120px 100px 140px 180px 120px' }}
      >
        {[
          { label: 'Process Name', icon: Terminal },
          { label: 'PID', icon: null },
          { label: 'CPU', icon: Cpu },
          { label: 'Memory', icon: MemoryStick },
          { label: 'User', icon: User },
          { label: 'Anomaly', icon: AlertTriangle },
          { label: 'Status', icon: null },
        ].map(({ label, icon: Icon }) => (
          <div key={label} className="flex items-center gap-1.5 px-3 py-2.5">
            {Icon && <Icon className="h-3 w-3 text-muted-foreground" />}
            <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              {label}
            </span>
          </div>
        ))}
      </div>

      {/* ── Tree Body ── */}
      <div className="flex-1 overflow-y-auto">
        {loading && (
          <div className="flex items-center justify-center gap-3 py-20 text-muted-foreground">
            <RefreshCw className="h-5 w-5 animate-spin text-purple-400" />
            <span className="text-sm">Loading process tree...</span>
          </div>
        )}

        {error && (
          <div className="flex items-center gap-3 m-6 rounded-lg border border-red-800 bg-red-950/30 px-4 py-3">
            <XCircle className="h-5 w-5 text-red-400 shrink-0" />
            <div>
              <p className="text-sm font-medium text-red-300">Failed to load process tree</p>
              <p className="text-xs text-red-400/70 mt-0.5">{error}</p>
            </div>
            <button onClick={fetchTree} className="ml-auto text-xs text-red-400 hover:text-red-300 underline">
              Retry
            </button>
          </div>
        )}

        {!loading && !error && tree.length === 0 && (
          <div className="flex flex-col items-center justify-center gap-3 py-20 text-muted-foreground">
            <Info className="h-8 w-8 text-dark-border" />
            <p className="text-sm">No process data available</p>
          </div>
        )}

        {!loading && !error && (
  showSuspiciousOnly
    ? flattenTree(tree)
        .filter(n => n.suspicious)
        .map(node => (
          <ProcessRow
            key={`${node.pid}-${node.name}`}
            node={{ ...node, children: [] }}
            depth={0}
            searchQuery={searchQuery}
            showSuspiciousOnly={false}
          />
        ))
    : tree.map(root => (
        <ProcessRow
          key={`${root.pid}-${root.name}`}
          node={root}
          depth={0}
          searchQuery={searchQuery}
          showSuspiciousOnly={false}
        />
      ))
)}
        
      </div>

     {/* ── Footer Legend ── */}
<div className="border-t border-dark-border bg-dark-surface/60 px-6 py-2.5">
  <div className="flex items-center gap-6 text-[11px] text-muted-foreground">
    <div className="flex items-center gap-1.5">
      <AlertTriangle className="h-3 w-3 text-red-400" />
      <span>Suspicious process</span>
    </div>
    <div className="flex items-center gap-1.5">
      <div className="h-2 w-2 rounded-full bg-cyber-green/60" />
      <span>Clean process</span>
    </div>
    <div className="flex items-center gap-1.5">
      <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border bg-orange-900/60 text-orange-300 border-orange-700 font-mono">T1059</span>
      <span>MITRE ATT&CK technique</span>
    </div>
    <div className="ml-auto flex items-center gap-1.5">
      <CheckCircle className="h-3 w-3 text-cyber-green" />
      <span>Auto-refresh every 30 seconds</span>
    </div>
  </div>
</div>

    </div>
  )
}