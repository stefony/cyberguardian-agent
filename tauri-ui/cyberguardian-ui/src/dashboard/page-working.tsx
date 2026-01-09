import { useState } from "react";
import { Shield, AlertTriangle, Activity } from "lucide-react";

export default function DashboardPage() {
  const [threatCount] = useState(0);
  const [scannedFiles] = useState(0);
  
  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">Dashboard</h1>
        <p className="text-muted-foreground">Welcome to CyberGuardian Desktop Agent</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {/* System Status */}
        <div className="bg-dark-surface p-6 rounded-lg border border-dark-border">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-cyber-green/10 rounded-lg">
              <Shield className="h-6 w-6 text-cyber-green" />
            </div>
            <h3 className="text-lg font-semibold">System Status</h3>
          </div>
          <p className="text-3xl font-bold text-cyber-green">Protected</p>
          <p className="text-sm text-muted-foreground mt-2">All systems operational</p>
        </div>

        {/* Threats Detected */}
        <div className="bg-dark-surface p-6 rounded-lg border border-dark-border">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-threat-critical/10 rounded-lg">
              <AlertTriangle className="h-6 w-6 text-threat-critical" />
            </div>
            <h3 className="text-lg font-semibold">Threats Detected</h3>
          </div>
          <p className="text-3xl font-bold text-threat-critical">{threatCount}</p>
          <p className="text-sm text-muted-foreground mt-2">Active threats</p>
        </div>

        {/* Files Scanned */}
        <div className="bg-dark-surface p-6 rounded-lg border border-dark-border">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-cyber-blue/10 rounded-lg">
              <Activity className="h-6 w-6 text-cyber-blue" />
            </div>
            <h3 className="text-lg font-semibold">Files Scanned</h3>
          </div>
          <p className="text-3xl font-bold text-cyber-blue">{scannedFiles}</p>
          <p className="text-sm text-muted-foreground mt-2">Total scans</p>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-dark-surface p-6 rounded-lg border border-dark-border">
        <h3 className="text-lg font-semibold mb-4">Quick Actions</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <button className="p-4 bg-dark-bg hover:bg-dark-bg/80 rounded-lg border border-dark-border transition-colors">
            <p className="font-medium">Run Scan</p>
          </button>
          <button className="p-4 bg-dark-bg hover:bg-dark-bg/80 rounded-lg border border-dark-border transition-colors">
            <p className="font-medium">View Threats</p>
          </button>
          <button className="p-4 bg-dark-bg hover:bg-dark-bg/80 rounded-lg border border-dark-border transition-colors">
            <p className="font-medium">Settings</p>
          </button>
          <button className="p-4 bg-dark-bg hover:bg-dark-bg/80 rounded-lg border border-dark-border transition-colors">
            <p className="font-medium">Reports</p>
          </button>
        </div>
      </div>
    </div>
  );
}