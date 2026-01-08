import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '@/lib/contexts/AuthContext'
import { cn } from '@/lib/utils'

import {
  Shield,
  Activity,
  AlertTriangle,
  Eye,
  Brain,
  BarChart3,
  Settings,
  Mail,
  Target,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Zap,
  LogOut,
  Calendar,
  Lock,
  Database,
  Fingerprint,
  ShieldAlert,
  RefreshCw,      // Updates
  FileJson,       // Configuration
  Gauge,          // Performance
  TrendingUp,
} from 'lucide-react'

interface SubItem {
  label: string
  href: string
}

interface NavItem {
  label: string
  href: string
  icon: React.ComponentType<{ className?: string }>
  badge?: number
  subItems?: SubItem[]
}

const navItems: NavItem[] = [
  {
    label: 'Dashboard',
    href: '/',
    icon: Activity,
  },
  {
    label: 'Executive',
    href: '/executive',
    icon: TrendingUp,
  },
  {
    label: 'Threats',
    href: '/threats',
    icon: AlertTriangle,
    badge: 3,
    subItems: [
      { label: 'Overview', href: '/threats' },
      { label: 'IOCs', href: '/threats/iocs' },
      { label: 'MITRE ATT&CK', href: '/threats/mitre' },
      { label: 'Threat Feeds', href: '/threats/feeds' },
    ],
  },
  {
    label: 'Detection',
    href: '/detection',
    icon: Zap,
  },
   {
    label: 'Protection',
    href: '/protection',
    icon: Shield,
  },
  {
    label: 'Scans',
    href: '/scans',
    icon: Calendar,
  },
  {
    label: 'Quarantine',
    href: '/quarantine',
    icon: Lock,
  },
  {
    label: 'Integrity',
    href: '/security/integrity',
    icon: Fingerprint,
  },
  {
    label: 'Tamper Protection',
    href: '/security/tamper',
    icon: ShieldAlert,
  },
  {
    label: 'Remediation',
    href: '/remediation',
    icon: Database,
    subItems: [
      { label: 'Overview', href: '/remediation' },
      { label: 'Registry Cleanup', href: '/remediation/registry' },
      { label: 'Services Cleanup', href: '/remediation/services' },
      { label: 'Tasks Cleanup', href: '/remediation/tasks' },
      { label: 'Deep Quarantine', href: '/remediation/quarantine' },
    ],
  },
  {
    label: 'Deception',
    href: '/deception',
    icon: Eye,
  },
  {
    label: 'Insights',
    href: '/insights',
    icon: Brain,
  },
  {
    label: 'ML Models',
    href: '/ml',
    icon: Zap,
  },
  {
    label: 'Analytics',
    href: '/analytics',
    icon: BarChart3,
  },
  {
    label: 'Email Scanner',
    href: '/emails',
    icon: Mail,
  },
  {
    label: 'Honeypots',
    href: '/honeypots',
    icon: Target,
  },
  {
    label: 'Performance',
    href: '/performance',
    icon: Gauge,
  },
  {
    label: 'Process Protection',
    href: '/process',
    icon: ShieldAlert,
  },
  {
    label: 'Updates',
    href: '/updates',
    icon: RefreshCw,
  },
  {
    label: 'Configuration',
    href: '/configuration',
    icon: FileJson,
  },
  {
    label: 'Settings',
    href: '/settings',
    icon: Settings,
  },
]

export function Sidebar() {
  const { logout } = useAuth()
  const [collapsed, setCollapsed] = useState(false)
  const [expandedItems, setExpandedItems] = useState<string[]>(['Threats'])
  const location = useLocation()
  const pathname = location.pathname

  const toggleExpanded = (label: string) => {
    setExpandedItems(prev =>
      prev.includes(label)
        ? prev.filter(item => item !== label)
        : [...prev, label]
    )
  }

  return (
    <aside
      className={cn(
        'fixed left-0 top-0 z-40 h-screen transition-all duration-300',
        'bg-dark-surface border-r border-dark-border',
        'flex flex-col',
        collapsed ? 'w-20' : 'w-64'
      )}
    >
      {/* Header */}
      <div className="flex h-16 items-center justify-between border-b border-dark-border px-4">
        {!collapsed && (
          <div className="flex items-center gap-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-cyber-purple to-cyber-blue">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold gradient-cyber">
                CyberGuardian
              </h1>
              <p className="text-xs text-muted-foreground">AI Security</p>
            </div>
          </div>
        )}

        {collapsed && (
          <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-cyber-purple to-cyber-blue">
            <Shield className="h-6 w-6 text-white" />
          </div>
        )}

        <button
          onClick={() => setCollapsed(!collapsed)}
          className={cn(
            'absolute -right-3 top-6 z-50 flex h-6 w-6 items-center justify-center rounded-full',
            'bg-dark-surface border border-dark-border shadow-lg',
            'hover:bg-dark-bg transition-all duration-200',
            'opacity-0 group-hover:opacity-100',
            collapsed && 'opacity-100'
          )}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 p-3 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon
          const isActive = pathname === item.href ||
                          (item.subItems && item.subItems.some(sub => pathname === sub.href))
          const isExpanded = expandedItems.includes(item.label)

          return (
            <div key={item.href}>
              {/* Main Item */}
              <div className="relative">
                <Link
                  to={item.href}
                  onClick={(e) => {
                    if (item.subItems && !collapsed) {
                      e.preventDefault()
                      toggleExpanded(item.label)
                    }
                  }}
                  className={cn(
                    'group relative flex items-center gap-3 rounded-lg px-3 py-2.5 transition-all duration-200', 
                    'hover:bg-dark-bg',
                    isActive && 'bg-dark-bg text-purple-500',
                    !isActive && 'text-muted-foreground hover:text-foreground'
                  )}
                >
                  {isActive && (
                    <div className="absolute left-0 top-1/2 h-8 w-1 -translate-y-1/2 rounded-r-full bg-purple-500" />
                  )}

                  <Icon
                    className={cn(
                      'h-5 w-5 flex-shrink-0 transition-colors',
                      isActive && 'text-purple-500',
                      !isActive && 'text-muted-foreground group-hover:text-foreground'
                    )}
                  />

                  {!collapsed && (
                    <>
                      <span className="flex-1 text-sm font-medium">
                        {item.label}
                      </span>

                      {item.badge && item.badge > 0 && (
                        <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-threat-critical px-1.5 text-xs font-bold text-white">
                          {item.badge}
                        </span>
                      )}

                      {item.subItems && (
                        <ChevronDown
                          className={cn(
                            'h-4 w-4 transition-transform duration-200',
                            isExpanded && 'rotate-180'
                          )}
                        />
                      )}
                    </>
                  )}

                  {collapsed && (
                    <div className="pointer-events-none absolute left-full ml-2 hidden rounded-md bg-dark-bg px-2 py-1 text-sm font-medium shadow-lg group-hover:block whitespace-nowrap">
                      {item.label}
                      {item.badge && item.badge > 0 && (
                        <span className="ml-2 rounded-full bg-threat-critical px-1.5 text-xs text-white">        
                          {item.badge}
                        </span>
                      )}
                    </div>
                  )}
                </Link>
              </div>

              {/* Sub Items */}
              {item.subItems && !collapsed && isExpanded && (
                <div className="ml-8 mt-1 space-y-1 border-l-2 border-dark-border pl-2">
                  {item.subItems.map((subItem) => {
                    const isSubActive = pathname === subItem.href
                    return (
                      <Link
                        key={subItem.href}
                        to={subItem.href}
                        className={cn(
                          'block rounded-md px-3 py-2 text-sm transition-colors',
                          isSubActive
                            ? 'bg-purple-500/10 text-purple-400 font-medium'
                            : 'text-muted-foreground hover:text-foreground hover:bg-dark-bg'
                        )}
                      >
                        {subItem.label}
                      </Link>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}
      </nav>

      {/* System Status */}
      <div className={cn(
        'border-t border-dark-border',
        collapsed ? 'p-2' : 'p-4'
      )}>
        {!collapsed && (
          <div className="space-y-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">System Status</span>
                <span className="flex items-center gap-1 text-cyber-green">
                  <span className="h-2 w-2 rounded-full bg-cyber-green animate-pulse" />
                  Protected
                </span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-dark-bg overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyber-blue to-cyber-green transition-all duration-500" 
                  style={{ width: '94%' }}
                />
              </div>
              <p className="text-xs text-muted-foreground">
                All systems operational
              </p>
            </div>

            <button
              onClick={logout}
              className="w-full flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground hover:text-red-500 hover:bg-dark-bg transition-all duration-200"
            >
              <LogOut className="h-5 w-5" />
              <span>Logout</span>
            </button>
          </div>
        )}

        {collapsed && (
          <div className="space-y-2">
            <div className="flex justify-center">
              <div className="h-8 w-8 rounded-full bg-cyber-green/20 flex items-center justify-center">
                <Shield className="h-4 w-4 text-cyber-green" />
              </div>
            </div>
            <button
              onClick={logout}
              className="w-full flex justify-center items-center py-2 text-muted-foreground hover:text-red-500 transition-colors"
              title="Logout"
            >
              <LogOut className="h-5 w-5" />
            </button>
          </div>
        )}
      </div>
    </aside>
  )
}