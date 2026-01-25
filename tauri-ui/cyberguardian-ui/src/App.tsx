import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./layout";

import DashboardPage from "./dashboard/page";
import ThreatsPage from "./threats/page";
import DetectionPage from "./detection/page";
import ProtectionPage from "./protection/page";
import ScansPage from "./scans/page";
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
import AnalyticsPage from "./analytics/page";
import PerformancePage from "./performance/page";
import EmailsPage from "./emails/page";
import HoneypotsPage from "./honeypots/page";
import ProcessPage from "./process/page";
import UpdatesPage from "./updates/page";
import ConfigurationPage from "./configuration/page";
import SettingsPage from "./settings/page";
import IOCsPage from "./threats/iocs/page";
import MITREPage from "./threats/mitre/page";
import FeedsPage from "./threats/feeds/page";

import LoginPage from "./auth/login/page";
import PricingPage from "./pricing/page";
import SuccessPage from "./success/page";

import { useOnlineStatus } from "@/hooks/useOnlineStatus";

function PlaceholderPage({ title }: { title: string }) {
  return (
    <div className="p-6">
      <h1 className="text-3xl font-bold mb-2">{title}</h1>
      <p className="text-muted-foreground">Page content coming soon...</p>
    </div>
  );
}

export default function App() {
  const isOnline = useOnlineStatus();

  return (
    <>
      {!isOnline && (
        <div className="w-full bg-yellow-500 text-black text-center text-xs py-1 z-50">
          ⚠ Offline Mode — Showing last cached data
        </div>
      )}

      <Routes>
        {/* ✅ PUBLIC routes (NO sidebar) */}
        <Route path="/auth/login" element={<LoginPage />} />
        <Route path="/pricing" element={<PricingPage />} />
        <Route path="/success" element={<SuccessPage />} />

        {/* ✅ PRIVATE routes (WITH sidebar via Layout) */}
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />

          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="threats" element={<ThreatsPage />} />
          <Route path="threats/iocs" element={<IOCsPage />} />
          <Route path="threats/mitre" element={<MITREPage />} />
          <Route path="threats/feeds" element={<FeedsPage />} />

          <Route path="detection" element={<DetectionPage />} />
          <Route path="protection" element={<ProtectionPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="settings" element={<SettingsPage />} />

          <Route path="quarantine" element={<QuarantinePage />} />
          <Route path="analytics" element={<AnalyticsPage />} />
          <Route path="executive" element={<ExecutivePage />} />
          <Route path="honeypots" element={<HoneypotsPage />} />
          <Route path="insights" element={<InsightsPage />} />
          <Route path="performance" element={<PerformancePage />} />
          <Route path="process" element={<ProcessPage />} />
          <Route path="remediation" element={<RemediationPage />} />
          <Route path="remediation/registry" element={<RegistryPage />} />
          <Route path="remediation/services" element={<ServicesPage />} />
          <Route path="remediation/tasks" element={<TasksPage />} />
          <Route path="remediation/quarantine" element={<DeepQuarantinePage />} />
          <Route path="updates" element={<UpdatesPage />} />
          <Route path="configuration" element={<ConfigurationPage />} />
          <Route path="deception" element={<DeceptionPage />} />
          <Route path="security" element={<PlaceholderPage title="Security" />} />
          <Route path="security/integrity" element={<IntegrityPage />} />
          <Route path="security/tamper" element={<TamperProtectionPage />} />
          <Route path="admin" element={<PlaceholderPage title="Admin" />} />
          <Route path="ml" element={<MLModelsPage />} />
          <Route path="emails" element={<EmailsPage />} />
        </Route>

        {/* fallback */}
        <Route path="*" element={<Navigate to="/auth/login" replace />} />
      </Routes>
    </>
  );
}
