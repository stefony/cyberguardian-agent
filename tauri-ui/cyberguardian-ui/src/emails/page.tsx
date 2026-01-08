"use client";

import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import CountUp from "react-countup";
import { Mail, Shield, AlertTriangle, RefreshCw, Trash2, Settings } from "lucide-react";
import { emailsApi } from "@/lib/api";
import Link from "next/link";
import ProtectedRoute from '@/components/ProtectedRoute';

export default function EmailsPage() {
  const [emailAccounts, setEmailAccounts] = useState<any[]>([]);
  const [selectedAccountId, setSelectedAccountId] = useState<number | null>(null);
  const [status, setStatus] = useState<any>(null);
  const [emails, setEmails] = useState<any[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [folder, setFolder] = useState("INBOX");
  const [limit, setLimit] = useState(10);
  const [loading, setLoading] = useState(true);

  // Fetch email accounts
  const fetchEmailAccounts = async () => {
  console.log('🔵 Fetching email accounts...');
  try {
    const response = await emailsApi.getAccounts();
    console.log('🔵 API Response:', response);
    
    if (response.success && response.data) {
      console.log('✅ Setting email accounts:', response.data);
      setEmailAccounts(response.data);
      if (response.data.length > 0 && !selectedAccountId) {
        console.log('✅ Setting selected account ID:', response.data[0].id);
        setSelectedAccountId(response.data[0].id);
      }
    } else {
      console.log('❌ Response not successful:', response);
    }
  } catch (err) {
    console.error("❌ Error fetching email accounts:", err);
  } finally {
    console.log('🔵 Setting loading to false');
    setLoading(false);
  }
};

  // Fetch status
  const fetchStatus = async () => {
    try {
      const response = await emailsApi.getStatus();
      if (response.success) {
        setStatus(response.data);
      }
    } catch (err) {
      console.error("Error fetching status:", err);
    }
  };

  // Scan emails
  const scanEmails = async () => {
    if (!selectedAccountId) {
      setError("Please select an email account first");
      return;
    }

    setIsScanning(true);
    setError(null);

    try {
      const response = await emailsApi.scan({ 
        account_id: selectedAccountId,
        folder, 
        limit 
      });

      if (response.success) {
        setEmails(response.data || []);
        await fetchEmailAccounts();
        await fetchStatus();
      } else {
        setError(response.error || "Failed to scan emails");
      }
    } catch (err) {
      console.error("Error scanning emails:", err);
      setError("Failed to scan emails");
    } finally {
      setIsScanning(false);
    }
  };

  useEffect(() => {
    fetchEmailAccounts();
    fetchStatus();
  }, []);

  const selectedAccount = emailAccounts.find(acc => acc.id === selectedAccountId);
  const totalScanned = status?.total_scanned || 0;
  const phishingDetected = status?.phishing_detected || 0;
  const safeEmails = status?.safe_emails || 0;

  // Loading skeleton
  if (loading) {
    return (
      <ProtectedRoute>
      <main className="pb-12">
        <div className="page-container page-hero pt-12 md:pt-16">
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
      </main>
      </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute> 
    <motion.main
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="pb-12"
    >
      {/* Hero */}
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
        className="page-container page-hero pt-12 md:pt-16"
      >
        <div className="flex items-center justify-between">
          <div>
            <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
              Email & Phishing Scanner
            </h1>
            <p className="mt-2 text-muted-foreground">
              Scan your inbox for phishing attempts and malicious emails
            </p>
          </div>
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.3, delay: 0.2 }}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <Link
              href="/settings"
              className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-blue-500 text-white hover:bg-blue-600 transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/50 relative z-50 cursor-pointer"
              style={{ pointerEvents: 'auto' }}
            >
              <Settings className="h-5 w-5" />
              Go to Settings
            </Link>
          </motion.div>
        </div>
      </motion.div>

      <div className="section">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* Scanner Status */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.1 }}
            whileHover={{ scale: 1.02, y: -4 }}
            className="stat-card group transition-all duration-300 hover:shadow-2xl hover:shadow-purple-500/20"
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="stat-label">Scanner Status</div>
                <div className="stat-value text-2xl">
                  {status?.configured ? (
                    <span className="text-green-500">Connected</span>
                  ) : (
                    <span className="text-red-500">Not Setup</span>
                  )}
                </div>
                {selectedAccount && (
                  <div className="text-sm text-muted-foreground mt-1">
                    {selectedAccount.email_address}
                  </div>
                )}
              </div>
              <motion.div
                animate={{ 
                  scale: status?.configured ? [1, 1.1, 1] : 1,
                  rotate: status?.configured ? 0 : [0, 10, -10, 0]
                }}
                transition={{ 
                  duration: 2, 
                  repeat: Infinity,
                  repeatDelay: status?.configured ? 2 : 1
                }}
              >
                <Mail className={`h-8 w-8 ${status?.configured ? 'text-green-500' : 'text-red-500'}`} />
              </motion.div>
            </div>
          </motion.div>

          {/* Total Scanned */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.2 }}
            whileHover={{ scale: 1.02, y: -4 }}
            className="stat-card stat-card--info group transition-all duration-300 hover:shadow-2xl hover:shadow-blue-500/20"
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="stat-label">Total Scanned</div>
                <div className="stat-value text-blue-500">
                  <CountUp end={totalScanned} duration={2} />
                </div>
              </div>
              <motion.div
                whileHover={{ rotate: 360 }}
                transition={{ duration: 0.5 }}
              >
                <Mail className="h-8 w-8 text-blue-500" />
              </motion.div>
            </div>
          </motion.div>

          {/* Phishing Detected */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.3 }}
            whileHover={{ scale: 1.02, y: -4 }}
            className="stat-card stat-card--error group transition-all duration-300 hover:shadow-2xl hover:shadow-red-500/20"
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="stat-label">Phishing Detected</div>
                <div className="stat-value text-red-500">
                  <CountUp end={phishingDetected} duration={2} />
                </div>
              </div>
              <motion.div
                animate={{ 
                  scale: phishingDetected > 0 ? [1, 1.2, 1] : 1,
                  rotate: phishingDetected > 0 ? [0, 5, -5, 0] : 0
                }}
                transition={{ 
                  duration: 0.5, 
                  repeat: phishingDetected > 0 ? Infinity : 0,
                  repeatDelay: 1
                }}
              >
                <AlertTriangle className="h-8 w-8 text-red-500" />
              </motion.div>
            </div>
          </motion.div>

          {/* Safe Emails */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.4 }}
            whileHover={{ scale: 1.02, y: -4 }}
            className="stat-card stat-card--ok group transition-all duration-300 hover:shadow-2xl hover:shadow-green-500/20"
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="stat-label">Safe Emails</div>
                <div className="stat-value text-green-500">
                  <CountUp end={safeEmails} duration={2} />
                </div>
              </div>
              <motion.div
                whileHover={{ scale: 1.2 }}
                transition={{ type: "spring", stiffness: 400 }}
              >
                <Shield className="h-8 w-8 text-green-500" />
              </motion.div>
            </div>
          </motion.div>
        </div>

        {/* No Accounts Warning */}
        <AnimatePresence mode="wait">
          {emailAccounts.length === 0 ? (
            <motion.div
              key="no-accounts"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.3 }}
              className="card-premium p-8 text-center relative z-50"
              style={{ pointerEvents: 'auto' }}
            >
              <motion.div
                animate={{ 
                  scale: [1, 1.1, 1],
                  rotate: [0, 5, -5, 0]
                }}
                transition={{ 
                  duration: 2, 
                  repeat: Infinity,
                  repeatType: "reverse"
                }}
              >
                <Mail className="h-16 w-16 mx-auto mb-4 text-muted-foreground opacity-50" />
              </motion.div>
              <h3 className="text-xl font-semibold mb-2">No Email Accounts Configured</h3>
              <p className="text-muted-foreground mb-4">
                Add an email account in Settings to start scanning for phishing emails
              </p>
              <motion.div
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <Link
                  href="/settings"
                  className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-blue-500 text-white hover:bg-blue-600 transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/50 relative z-50 cursor-pointer"
                  style={{ pointerEvents: 'auto' }}
                >
                  <Settings className="h-5 w-5" />
                  Go to Settings
                </Link>
              </motion.div>
            </motion.div>
          ) : (
            <motion.div
              key="with-accounts"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              {/* Scan Configuration */}
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: 0.5 }}
                className="card-premium p-6 mb-8 hover:shadow-xl transition-shadow duration-300"
              >
                <h3 className="text-lg font-semibold mb-4">Scan Configuration</h3>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  {/* Email Account Selection */}
                  <motion.div whileHover={{ scale: 1.01 }}>
                    <label className="block text-sm font-medium mb-2">Email Account</label>
                    <select
                      value={selectedAccountId || ''}
                      onChange={(e) => setSelectedAccountId(Number(e.target.value))}
                      className="w-full px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all hover:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:shadow-lg focus:shadow-blue-500/10"
                      style={{ colorScheme: 'dark' }}
                    >
                      {emailAccounts.map((account) => (
                        <option key={account.id} value={account.id}>
                          {account.email_address} ({account.total_scanned} scanned)
                        </option>
                      ))}
                    </select>
                  </motion.div>

                  {/* Email Folder */}
                  <motion.div whileHover={{ scale: 1.01 }}>
                    <label className="block text-sm font-medium mb-2">Email Folder</label>
                    <select
                      value={folder}
                      onChange={(e) => setFolder(e.target.value)}
                      className="w-full px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all hover:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:shadow-lg focus:shadow-purple-500/10"
                      style={{ colorScheme: 'dark' }}
                    >
                      <option value="INBOX">Inbox</option>
                      <option value="Spam">Spam</option>
                      <option value="Sent">Sent</option>
                      <option value="Drafts">Drafts</option>
                    </select>
                  </motion.div>

                  {/* Email Limit */}
                  <motion.div whileHover={{ scale: 1.01 }}>
                    <label className="block text-sm font-medium mb-2">Email Limit</label>
                    <select
                      value={limit}
                      onChange={(e) => setLimit(Number(e.target.value))}
                      className="w-full px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all hover:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:shadow-lg focus:shadow-cyan-500/10"
                      style={{ colorScheme: 'dark' }}
                    >
                      <option value={10}>10 emails</option>
                      <option value={20}>20 emails</option>
                      <option value={50}>50 emails</option>
                      <option value={100}>100 emails</option>
                    </select>
                  </motion.div>
                </div>

                {/* Scan Button */}
                <motion.button
                  whileHover={{ scale: 1.02, y: -2 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={scanEmails}
                  disabled={isScanning || !selectedAccountId}
                  className="w-full px-6 py-3 rounded-lg bg-gradient-to-r from-purple-500 to-pink-500 text-white font-semibold hover:from-purple-600 hover:to-pink-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/50 flex items-center justify-center gap-2"
                >
                  <RefreshCw className={`h-5 w-5 ${isScanning ? 'animate-spin' : ''}`} />
                  {isScanning ? 'Scanning...' : 'Scan Emails'}
                </motion.button>

                <AnimatePresence>
                  {error && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="mt-4 p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500"
                    >
                      {error}
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>

              {/* Scan Results */}
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: 0.6 }}
                className="card-premium p-6 hover:shadow-xl transition-shadow duration-300"
              >
                <h3 className="text-lg font-semibold mb-4">
                  Scan Results (<CountUp end={emails.length} duration={1} /> emails)
                </h3>

                <AnimatePresence mode="wait">
                  {emails.length === 0 ? (
                    <motion.div
                      key="empty"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="text-center py-12 text-muted-foreground"
                    >
                      <motion.div
                        animate={{ scale: [1, 1.1, 1], rotate: [0, 5, -5, 0] }}
                        transition={{ duration: 2, repeat: Infinity, repeatType: "reverse" }}
                      >
                        <Mail className="h-16 w-16 mx-auto mb-4 opacity-50" />
                      </motion.div>
                      <p>No emails scanned yet</p>
                      <p className="text-sm">Configure your email credentials and click "Scan Emails" to start</p>
                    </motion.div>
                  ) : (
                    <motion.div
                      key="results"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="space-y-4"
                    >
                      {emails.map((email, index) => (
                        <motion.div
                          key={index}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ duration: 0.3, delay: index * 0.05 }}
                          whileHover={{ scale: 1.01, x: 4 }}
                          className={`p-4 rounded-lg border-2 transition-all ${
                            email.threat_level === 'dangerous'
                              ? 'bg-red-500/5 border-red-500/30 hover:border-red-500/50 hover:shadow-lg hover:shadow-red-500/20'
                              : email.threat_level === 'suspicious'
                              ? 'bg-yellow-500/5 border-yellow-500/30 hover:border-yellow-500/50 hover:shadow-lg hover:shadow-yellow-500/20'
                              : 'bg-green-500/5 border-green-500/30 hover:border-green-500/50 hover:shadow-lg hover:shadow-green-500/20'
                          }`}
                        >
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex-1">
                              <h4 className="font-semibold text-foreground">{email.subject}</h4>
                              <div className="text-sm text-muted-foreground">
                                From: {email.sender}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {email.date}
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <motion.div
                                whileHover={{ scale: 1.1 }}
                                className={`px-3 py-1 rounded-full text-xs font-semibold ${
                                  email.threat_level === 'dangerous'
                                    ? 'bg-red-500/20 text-red-500'
                                    : email.threat_level === 'suspicious'
                                    ? 'bg-yellow-500/20 text-yellow-500'
                                    : 'bg-green-500/20 text-green-500'
                                }`}
                              >
                                <CountUp end={Math.round(email.phishing_score)} duration={1.5} />/100
                              </motion.div>
                              <motion.span
                                whileHover={{ scale: 1.05 }}
                                className={`badge ${
                                  email.threat_level === 'dangerous'
                                    ? 'badge--error'
                                    : email.threat_level === 'suspicious'
                                    ? 'badge--warning'
                                    : 'badge--ok'
                                }`}
                              >
                                {email.threat_level.toUpperCase()}
                              </motion.span>
                            </div>
                          </div>

                          {/* Indicators */}
                          {email.indicators && email.indicators.length > 0 && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: 'auto' }}
                              transition={{ delay: 0.2 }}
                              className="mt-3 space-y-1"
                            >
                              {email.indicators.slice(0, 3).map((indicator: string, i: number) => (
                                <motion.div
                                  key={i}
                                  initial={{ opacity: 0, x: -10 }}
                                  animate={{ opacity: 1, x: 0 }}
                                  transition={{ delay: 0.3 + i * 0.1 }}
                                  className="flex items-center gap-2 text-sm text-muted-foreground"
                                >
                                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                                  {indicator}
                                </motion.div>
                              ))}
                              {email.indicators.length > 3 && (
                                <div className="text-sm text-muted-foreground">
                                  +{email.indicators.length - 3} more indicators
                                </div>
                              )}
                            </motion.div>
                          )}

                          {/* URLs */}
                          {email.urls && email.urls.length > 0 && (
                            <div className="mt-2 text-sm text-muted-foreground">
                              🔗 {email.urls.length} URL(s) detected
                            </div>
                          )}

                          {/* Recommendations */}
                          {email.is_phishing && email.recommendations && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: 'auto' }}
                              transition={{ delay: 0.4 }}
                              className="mt-3 p-3 rounded-lg bg-red-500/10 border border-red-500/30"
                            >
                              <div className="font-semibold text-red-500 mb-2">⚠️ Recommendations:</div>
                              <ul className="text-sm space-y-1 text-red-400">
                                {email.recommendations.slice(0, 2).map((rec: string, i: number) => (
                                  <li key={i}>• {rec}</li>
                                ))}
                              </ul>
                            </motion.div>
                          )}
                        </motion.div>
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.main>
    </ProtectedRoute>
  );
}