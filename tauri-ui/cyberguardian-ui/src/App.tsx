import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./layout";
import DashboardPage from "./dashboard/page";
import ThreatsPage from "./threats/page";
import DetectionPage from "./detection/page";
import ProtectionPage from "./protection/page";
import ScansPage from "./scans/page";
import SettingsPage from "./settings/page-simple";
import ExecutivePage from "./executive/page";
import QuarantinePage from "./quarantine/page";
import IntegrityPage from "./security/integrity/page";
import TamperProtectionPage from "./security/tamper/page";
import RemediationPage from "./remediation/page";
import RegistryPage from "./remediation/registry/page";
import ServicesPage from "./remediation/services/page";
import TasksPage from "./remediation/tasks/page";
import DeepQuarantinePage from "./remediation/quarantine/page";
import DeceptionPage from "./deception/page";
import InsightsPage from "./insights/page";
import MLModelsPage from "./ml/page";


// Temporary placeholder for other pages
function PlaceholderPage({ title }: { title: string }) {
  return (
    <div className="p-6">
      <h1 className="text-3xl font-bold mb-2">{title}</h1>
      <p className="text-muted-foreground">Page content coming soon...</p>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="threats" element={<ThreatsPage />} />
        <Route path="detection" element={<DetectionPage />} />
        <Route path="protection" element={<ProtectionPage />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="settings" element={<SettingsPage />} />
        
        {/* Placeholder routes */}
        <Route path="quarantine" element={<QuarantinePage />} />
        <Route path="analytics" element={<PlaceholderPage title="Analytics" />} />
        <Route path="executive" element={<ExecutivePage />} />
        <Route path="honeypots" element={<PlaceholderPage title="Honeypots" />} />
        <Route path="insights" element={<InsightsPage />} />
        <Route path="performance" element={<PlaceholderPage title="Performance" />} />
        <Route path="process" element={<PlaceholderPage title="Process Protection" />} />
        <Route path="remediation" element={<RemediationPage />} />
        <Route path="remediation/registry" element={<RegistryPage />} />
        <Route path="remediation/services" element={<ServicesPage />} />
        <Route path="remediation/tasks" element={<TasksPage />} />
        <Route path="remediation/quarantine" element={<DeepQuarantinePage />} />
        <Route path="updates" element={<PlaceholderPage title="Updates" />} />
        <Route path="configuration" element={<PlaceholderPage title="Configuration" />} />
        <Route path="deception" element={<DeceptionPage />} />
        <Route path="security" element={<PlaceholderPage title="Security" />} />
        <Route path="security/integrity" element={<IntegrityPage />} />
        <Route path="security/tamper" element={<TamperProtectionPage />} />
        <Route path="admin" element={<PlaceholderPage title="Admin" />} />
        <Route path="ml" element={<MLModelsPage />} />
        <Route path="emails" element={<PlaceholderPage title="Email Scanner" />} />
      </Route>
    </Routes>
  );
}