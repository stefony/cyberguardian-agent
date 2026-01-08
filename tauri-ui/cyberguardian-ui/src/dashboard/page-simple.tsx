export default function DashboardPage() {
  return (
    <div className="p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">Dashboard</h1>
        <p className="text-muted-foreground">Welcome to CyberGuardian Desktop Agent</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-dark-surface p-6 rounded-lg border border-dark-border">
          <h3 className="text-lg font-semibold mb-2">System Status</h3>
          <p className="text-3xl font-bold text-cyber-green">Protected</p>
        </div>

        <div className="bg-dark-surface p-6 rounded-lg border border-dark-border">
          <h3 className="text-lg font-semibold mb-2">Threats Detected</h3>
          <p className="text-3xl font-bold text-threat-critical">0</p>
        </div>

        <div className="bg-dark-surface p-6 rounded-lg border border-dark-border">
          <h3 className="text-lg font-semibold mb-2">Files Scanned</h3>
          <p className="text-3xl font-bold text-cyber-blue">0</p>
        </div>
      </div>
    </div>
  );
}