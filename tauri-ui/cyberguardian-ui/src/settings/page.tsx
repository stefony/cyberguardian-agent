  "use client";

  import { useEffect, useState } from "react";
  import { Settings as SettingsIcon, Bell, Palette, Shield, Info, Key, Save, RotateCcw, Check, Mail, Plus, Trash2, Loader2 } from "lucide-react";
  import { settingsApi, emailsApi } from "@/lib/api"; 
  import ExportImportConfig from "@/components/ExportImportConfig";
  import { FileJson } from "lucide-react";
  import ProtectedRoute from '@/components/ProtectedRoute';
  

  // Types
  type NotificationSettings = {
    email_alerts: boolean;
    desktop_alerts: boolean;
    critical_only: boolean;
    alert_sound: boolean;
  };

  type AppearanceSettings = {
    theme: string;
    compact_mode: boolean;
    animations_enabled: boolean;
  };



  type Settings = {
    notifications: NotificationSettings;
    appearance: AppearanceSettings;
    last_updated: string;
  };

  type SystemInfo = {
    os: string;
    os_version: string;
    python_version: string;
    cpu_count: number;
    total_memory_gb: number;
    hostname: string;
  };

  type LicenseInfo = {
    license_type: string;
    status: string;
    expires_at: string | null;
    features: string[];
  };

  export default function SettingsPage() {
    const [settings, setSettings] = useState<Settings | null>(null);
    const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
    const [licenseInfo, setLicenseInfo] = useState<LicenseInfo | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [isSaving, setIsSaving] = useState(false);
    const [saveSuccess, setSaveSuccess] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Email Accounts State
    const [emailAccounts, setEmailAccounts] = useState<any[]>([]);
    const [showAddEmailForm, setShowAddEmailForm] = useState(false);
    const [isAddingEmail, setIsAddingEmail] = useState(false);
    const [newEmailForm, setNewEmailForm] = useState({
      provider: '',
      email_address: '',
      imap_host: '',
      imap_port: 993,
      password: '',
      auto_scan_enabled: true,
      scan_interval_hours: 24,
      folders_to_scan: 'INBOX'
    });

    // Fetch settings
 const fetchSettings = async () => {
  try {
    setIsLoading(true);
    const response = await settingsApi.getSettings();
    if (response.success && response.data) {
      setSettings(response.data);
      setError(null);
    } else {
      console.log('🟡 Using mock settings');
      const mockSettings: Settings = {
        notifications: {
          email_alerts: true,
          desktop_alerts: true,
          critical_only: false,
          alert_sound: true
        },
        appearance: {
          theme: 'dark',
          compact_mode: false,
          animations_enabled: true
        },
        last_updated: new Date().toISOString()
      };
      setSettings(mockSettings);
      setError(null);
    }
  } catch (err) {
    console.error("Error fetching settings:", err);
    console.log('🟡 Using mock settings (error fallback)');
    const mockSettings: Settings = {
      notifications: {
        email_alerts: true,
        desktop_alerts: true,
        critical_only: false,
        alert_sound: true
      },
      appearance: {
        theme: 'dark',
        compact_mode: false,
        animations_enabled: true
      },
      last_updated: new Date().toISOString()
    };
    setSettings(mockSettings);
    setError("Could not load settings");
  } finally {
    setIsLoading(false);
  }
};

    // Fetch system info
const fetchSystemInfo = async () => {
  try {
    const response = await settingsApi.getSystemInfo();
    if (response.success && response.data) {
      setSystemInfo(response.data);
    } else {
      console.log('🟡 Using mock system info');
      const mockSystemInfo: SystemInfo = {
        os: 'Windows',
        os_version: '10.0.19045',
        python_version: '3.11.5',
        cpu_count: 8,
        total_memory_gb: 16,
        hostname: 'DESKTOP-CG-01'
      };
      setSystemInfo(mockSystemInfo);
    }
  } catch (err) {
    console.error("Error fetching system info:", err);
    console.log('🟡 Using mock system info (error fallback)');
    const mockSystemInfo: SystemInfo = {
      os: 'Windows',
      os_version: '10.0.19045',
      python_version: '3.11.5',
      cpu_count: 8,
      total_memory_gb: 16,
      hostname: 'DESKTOP-CG-01'
    };
    setSystemInfo(mockSystemInfo);
  }
};

    // Fetch license info
   const fetchLicenseInfo = async () => {
  try {
    // Read from localStorage
    const licenseKey = localStorage.getItem('license_key');
    const licensePlan = localStorage.getItem('license_plan');
    const licenseExpires = localStorage.getItem('license_expires');
    
    if (licenseKey && licensePlan) {
      setLicenseInfo({
        license_type: licensePlan.toUpperCase(),
        status: 'active',
        expires_at: licenseExpires,
        features: [
          'Real-time threat detection',
          'Advanced AI analysis',
          'Honeypot deception layer',
          licensePlan === 'business' || licensePlan === 'enterprise' ? 'Unlimited scans' : 'Limited scans',
          licensePlan === 'business' || licensePlan === 'enterprise' ? 'Priority support' : 'Basic support',
          licensePlan === 'enterprise' ? 'Custom alerts' : ''
        ].filter(Boolean)
      });
    } else {
      console.log('🟡 Using mock license info');
      setLicenseInfo({
        license_type: 'BUSINESS',
        status: 'active',
        expires_at: '2027-01-07T00:00:00Z',
        features: [
          'Real-time threat detection',
          'Advanced AI analysis',
          'Honeypot deception layer',
          'Unlimited scans',
          'Priority support'
        ]
      });
    }
  } catch (err) {
    console.error("Error fetching license info:", err);
    console.log('🟡 Using mock license info (error fallback)');
    setLicenseInfo({
      license_type: 'BUSINESS',
      status: 'active',
      expires_at: '2027-01-07T00:00:00Z',
      features: [
        'Real-time threat detection',
        'Advanced AI analysis',
        'Honeypot deception layer',
        'Unlimited scans',
        'Priority support'
      ]
    });
  }
};

  // Fetch email accounts
const fetchEmailAccounts = async () => {
  try {
    const response = await emailsApi.getAccounts();
    if (response.success && Array.isArray(response.data)) {
      setEmailAccounts(response.data);
    } else {
      console.log('🟡 Using mock email accounts');
      const mockEmailAccounts = [
        { id: 1, email_address: 'security@company.com', provider: 'Gmail', auto_scan_enabled: true, scan_interval_hours: 24, total_scanned: 1247, phishing_detected: 23 },
        { id: 2, email_address: 'admin@company.com', provider: 'Outlook', auto_scan_enabled: false, scan_interval_hours: 48, total_scanned: 856, phishing_detected: 12 }
      ];
      setEmailAccounts(mockEmailAccounts);
    }
  } catch (err) {
    console.error("Error fetching email accounts:", err);
    console.log('🟡 Using mock email accounts (error fallback)');
    const mockEmailAccounts = [
      { id: 1, email_address: 'security@company.com', provider: 'Gmail', auto_scan_enabled: true, scan_interval_hours: 24, total_scanned: 1247, phishing_detected: 23 },
      { id: 2, email_address: 'admin@company.com', provider: 'Outlook', auto_scan_enabled: false, scan_interval_hours: 48, total_scanned: 856, phishing_detected: 12 }
    ];
    setEmailAccounts(mockEmailAccounts);
  }
};

    // Add email account
    const handleAddEmailAccount = async () => {
      if (!newEmailForm.email_address || !newEmailForm.password || !newEmailForm.provider) {
        alert("Please fill in all required fields");
        return;
      }

      try {
        setIsAddingEmail(true);
        const response = await emailsApi.addAccount({
          email_address: newEmailForm.email_address,
          provider: newEmailForm.provider,
          imap_host: newEmailForm.imap_host,
          imap_port: newEmailForm.imap_port,
          password: newEmailForm.password,
          auto_scan_enabled: newEmailForm.auto_scan_enabled,
          scan_interval_hours: newEmailForm.scan_interval_hours,
          folders_to_scan: newEmailForm.folders_to_scan
        });

        if (response.success) {
          alert("✅ Email account added successfully!");
          setShowAddEmailForm(false);
          setNewEmailForm({
            provider: '',
            email_address: '',
            imap_host: '',
            imap_port: 993,
            password: '',
            auto_scan_enabled: true,
            scan_interval_hours: 24,
            folders_to_scan: 'INBOX'
          });
          await fetchEmailAccounts();
        } else {
          alert(`❌ Failed to add email account: ${response.error}`);
        }
      } catch (err) {
        console.error("Error adding email account:", err);
        alert("❌ Failed to add email account");
      } finally {
        setIsAddingEmail(false);
      }
    };

    // Toggle auto-scan
    const handleToggleAutoScan = async (accountId: number, enabled: boolean) => {
      try {
        const response = await emailsApi.updateAccount(accountId, {
          auto_scan_enabled: enabled
        });

        if (response.success) {
          await fetchEmailAccounts();
        } else {
          alert(`Failed to update: ${response.error}`);
        }
      } catch (err) {
        console.error("Error toggling auto-scan:", err);
        alert("Failed to update auto-scan");
      }
    };

    // Delete email account
    const handleDeleteAccount = async (accountId: number) => {
      if (!confirm("Are you sure you want to delete this email account?")) return;

      try {
        const response = await emailsApi.deleteAccount(accountId);

        if (response.success) {
          alert("✅ Email account deleted successfully");
          await fetchEmailAccounts();
        } else {
          alert(`❌ Failed to delete: ${response.error}`);
        }
      } catch (err) {
        console.error("Error deleting email account:", err);
        alert("❌ Failed to delete email account");
      }
    };

    // Save settings
    const handleSave = async () => {
      if (!settings) return;
      
      try {
        setIsSaving(true);
        const response = await settingsApi.saveSettings(settings);
        
        if (response.success) {
          setSaveSuccess(true);
          setTimeout(() => setSaveSuccess(false), 3000);
        } else {
          alert(response.error || "Failed to save settings");
        }
      } catch (err) {
        console.error("Error saving settings:", err);
        alert("Failed to save settings");
      } finally {
        setIsSaving(false);
      }
    };

    // Reset settings
    const handleReset = async () => {
      if (!confirm("Are you sure you want to reset all settings to default?")) return;
      
      try {
        const response = await settingsApi.resetSettings();
        
        if (response.success) {
          await fetchSettings();
          alert("Settings reset to default successfully!");
        } else {
          alert(response.error || "Failed to reset settings");
        }
      } catch (err) {
        console.error("Error resetting settings:", err);
        alert("Failed to reset settings");
      }
    };

    // Initial load
    useEffect(() => {
      fetchSettings();
      fetchSystemInfo();
      fetchLicenseInfo();
      fetchEmailAccounts();
    }, []);

    // Update settings helper
    const updateSettings = (section: keyof Settings, key: string, value: any) => {
      if (!settings) return;
      setSettings({
        ...settings,
        [section]: {
          ...(settings[section] as any),
          [key]: value,
        },
      });
    };

    // Toggle component
    const Toggle = ({ enabled, onChange }: { enabled: boolean; onChange: () => void }) => (
      <button
        onClick={onChange}
        className={`
          relative inline-flex h-6 w-11 items-center rounded-full transition-all duration-300
          ${enabled ? 'bg-purple-500' : 'bg-gray-600'}
          hover:scale-105 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 focus:ring-offset-gray-900
        `}
      >
        <span
          className={`
            inline-block h-4 w-4 transform rounded-full bg-white transition-transform duration-300
            ${enabled ? 'translate-x-6' : 'translate-x-1'}
          `}
        />
      </button>
    );

    if (isLoading) {
      return (
        <ProtectedRoute>
        <main className="section text-center py-12">
          <SettingsIcon className="h-8 w-8 animate-spin mx-auto text-purple-500" />
          <p className="mt-4 text-muted-foreground">Loading settings...</p>
        </main>
        </ProtectedRoute>
      );
    }

    if (error || !settings) {
      return (
        <main className="section text-center py-12">
          <SettingsIcon className="h-8 w-8 mx-auto text-red-500" />
          <p className="mt-4 text-red-500">{error || "Failed to load settings"}</p>
        </main>
      );
    }

    return (
      <ProtectedRoute>
      <main className="pb-12">
        {/* Hero */}
        <div className="page-container page-hero pt-12 md:pt-16">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
                Settings
              </h1>
              <p className="mt-2 text-muted-foreground">
                Configure your CyberGuardian preferences and system settings
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={handleReset}
                className="px-4 py-2 rounded-lg bg-red-500/10 text-red-500 hover:bg-red-500/20 border-2 border-red-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-red-500/50 flex items-center gap-2"
              >
                <RotateCcw className="h-4 w-4" />
                Reset
              </button>

              <button
                onClick={handleSave}
                disabled={isSaving}
                className="px-4 py-2 rounded-lg bg-purple-500/10 text-purple-500 hover:bg-purple-500/20 border-2 border-purple-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/50 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {saveSuccess ? (
                  <>
                    <Check className="h-4 w-4" />
                    Saved!
                  </>
                ) : (
                  <>
                    <Save className={`h-4 w-4 ${isSaving ? 'animate-spin' : ''}`} />
                    Save
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        <div className="section">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left Column - Settings */}
            <div className="lg:col-span-2 space-y-6">
              {/* Notifications */}
              <div className="card-premium p-6 transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/20">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Bell className="h-5 w-5 text-purple-500" />
                  Notifications
                </h3>

                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">Email Alerts</div>
                      <div className="text-sm text-muted-foreground">Receive threat alerts via email</div>
                    </div>
                    <Toggle
                      enabled={settings.notifications.email_alerts}
                      onChange={() => updateSettings('notifications', 'email_alerts', !settings.notifications.email_alerts)}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">Desktop Alerts</div>
                      <div className="text-sm text-muted-foreground">Show desktop notifications</div>
                    </div>
                    <Toggle
                      enabled={settings.notifications.desktop_alerts}
                      onChange={() => updateSettings('notifications', 'desktop_alerts', !settings.notifications.desktop_alerts)}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">Critical Only</div>
                      <div className="text-sm text-muted-foreground">Only notify for critical threats</div>
                    </div>
                    <Toggle
                      enabled={settings.notifications.critical_only}
                      onChange={() => updateSettings('notifications', 'critical_only', !settings.notifications.critical_only)}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">Alert Sound</div>
                      <div className="text-sm text-muted-foreground">Play sound for new alerts</div>
                    </div>
                    <Toggle
                      enabled={settings.notifications.alert_sound}
                      onChange={() => updateSettings('notifications', 'alert_sound', !settings.notifications.alert_sound)}
                    />
                  </div>
                </div>
              </div>

              {/* Appearance */}
              <div className="card-premium p-6 transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/20">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Palette className="h-5 w-5 text-cyan-500" />
                  Appearance
                </h3>

                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">Theme</div>
                      <div className="text-sm text-muted-foreground">Choose your preferred theme</div>
                    </div>
                    <select
                      value={settings.appearance.theme}
                      onChange={(e) => updateSettings('appearance', 'theme', e.target.value)}
                      className="px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all duration-300 hover:border-cyan-400 hover:bg-cyan-500/5 focus:outline-none focus:ring-2 focus:ring-cyan-500 cursor-pointer relative z-50"
                      style={{ 
                        pointerEvents: 'auto',
                        colorScheme: 'dark'
                      }}
                    >
                      <option value="dark" className="bg-[#0a0e27] text-white">Dark</option>
                      <option value="light" className="bg-[#0a0e27] text-white">Light</option>
                      <option value="auto" className="bg-[#0a0e27] text-white">Auto</option>
                    </select>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">Compact Mode</div>
                      <div className="text-sm text-muted-foreground">Reduce spacing and padding</div>
                    </div>
                    <Toggle
                      enabled={settings.appearance.compact_mode}
                      onChange={() => updateSettings('appearance', 'compact_mode', !settings.appearance.compact_mode)}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">Animations</div>
                      <div className="text-sm text-muted-foreground">Enable smooth animations</div>
                    </div>
                    <Toggle
                      enabled={settings.appearance.animations_enabled}
                      onChange={() => updateSettings('appearance', 'animations_enabled', !settings.appearance.animations_enabled)}
                    />
                  </div>
                </div>
              </div>

            

              {/* Email Accounts */}
              <div className="card-premium p-6 transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/20">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Mail className="h-5 w-5 text-blue-500" />
                  Email Accounts
                </h3>

                {/* Email Accounts List */}
                {emailAccounts.length > 0 ? (
                  <div className="space-y-3 mb-4">
                    {emailAccounts.map((account: any) => (
                      <div
                        key={account.id}
                        className="p-4 rounded-lg bg-card/50 border border-border hover:border-blue-500/50 transition-all"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div>
                            <div className="font-medium text-foreground">{account.email_address}</div>
                            <div className="text-sm text-muted-foreground">
                              {account.provider} • {account.total_scanned} scanned • {account.phishing_detected} phishing
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <Toggle
                              enabled={account.auto_scan_enabled}
                              onChange={() => handleToggleAutoScan(account.id, !account.auto_scan_enabled)}
                            />
                            <button
                              onClick={() => handleDeleteAccount(account.id)}
                              className="p-2 rounded-lg bg-red-500/10 text-red-500 hover:bg-red-500/20 transition-all"
                              title="Delete account"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </div>
                        </div>
                        {account.auto_scan_enabled && (
                          <div className="text-xs text-muted-foreground">
                            Auto-scan every {account.scan_interval_hours}h • Folders: {account.folders_to_scan}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-6 text-muted-foreground">
                    <Mail className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No email accounts configured</p>
                    <p className="text-sm">Add an account to start scanning for phishing emails</p>
                  </div>
                )}

                {/* Add Email Account Button */}
              <button
    onClick={(e) => {
      e.preventDefault();
      e.stopPropagation();
      setShowAddEmailForm(!showAddEmailForm);
    }}
    className="w-full px-4 py-2 rounded-lg bg-blue-500/10 text-blue-500 hover:bg-blue-500/20 border-2 border-blue-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-blue-500/50 flex items-center justify-center gap-2 relative z-50 cursor-pointer"
    style={{ pointerEvents: 'auto' }}
  >
    <Plus className="h-4 w-4" />
    {showAddEmailForm ? 'Cancel' : 'Add Email Account'}
  </button>

  {/* Add Email Form */}
  {showAddEmailForm && (
    <div className="mt-4 p-4 rounded-lg bg-card/50 border border-blue-500/30 space-y-4 relative z-50">
      
      {/* Instructions Banner */}
      <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/30 text-sm">
        <div className="flex items-start gap-2">
          <Info className="h-5 w-5 text-blue-500 flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold text-blue-500 mb-1">Setup Instructions:</div>
            <ol className="list-decimal list-inside space-y-1 text-muted-foreground">
              <li>Enable 2-Factor Authentication on your email account</li>
              <li>Generate an App Password (not your regular password)</li>
              <li>Use the App Password below to connect</li>
            </ol>
          </div>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium mb-2">Email Provider</label>
        <select
          value={newEmailForm.provider}
          onChange={(e) => {
            const provider = e.target.value;
            setNewEmailForm({
              ...newEmailForm,
              provider,
              imap_host: provider === 'gmail' ? 'imap.gmail.com' : 
                        provider === 'outlook' ? 'outlook.office365.com' : 
                        provider === 'yahoo' ? 'imap.mail.yahoo.com' : '',
              imap_port: 993
            });
          }}
          className="w-full px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all hover:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500 relative z-50 cursor-pointer"
          style={{ 
            colorScheme: 'dark',
            pointerEvents: 'auto',
            backgroundColor: 'rgb(15, 23, 42)',
            color: 'white'
          }}
        >
          <option value="" style={{ backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}>Select provider</option>
          <option value="gmail" style={{ backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}>Gmail</option>
          <option value="outlook" style={{ backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}>Outlook / Office 365</option>
          <option value="yahoo" style={{ backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}>Yahoo Mail</option>
          <option value="other" style={{ backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}>Other (Custom)</option>
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium mb-2">Email Address</label>
        <input
          type="email"
          value={newEmailForm.email_address}
          onChange={(e) => setNewEmailForm({ ...newEmailForm, email_address: e.target.value })}
          placeholder="your.email@example.com"
          className="w-full px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all hover:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500 relative z-50"
          style={{ pointerEvents: 'auto' }}
        />
      </div>

      {newEmailForm.provider === 'other' && (
        <>
          <div>
            <label className="block text-sm font-medium mb-2">IMAP Host</label>
            <input
              type="text"
              value={newEmailForm.imap_host}
              onChange={(e) => setNewEmailForm({ ...newEmailForm, imap_host: e.target.value })}
              placeholder="imap.example.com"
              className="w-full px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all hover:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500 relative z-50"
              style={{ pointerEvents: 'auto' }}
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-2">IMAP Port</label>
            <input
              type="number"
              value={newEmailForm.imap_port}
              onChange={(e) => setNewEmailForm({ ...newEmailForm, imap_port: parseInt(e.target.value) })}
              placeholder="993"
              className="w-full px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all hover:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500 relative z-50"
              style={{ pointerEvents: 'auto' }}
            />
          </div>
        </>
      )}

      <div>
        <label className="block text-sm font-medium mb-2">
          App Password
          {newEmailForm.provider === 'gmail' && (
            <span className="text-xs text-blue-400 ml-2">
              (16-character code, not your Gmail password)
            </span>
          )}
          {newEmailForm.provider === 'outlook' && (
            <span className="text-xs text-blue-400 ml-2">
              (Not your Microsoft account password)
            </span>
          )}
        </label>
        <input
          type="password"
          value={newEmailForm.password}
          onChange={(e) => setNewEmailForm({ ...newEmailForm, password: e.target.value })}
          placeholder="Enter app password"
          className="w-full px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all hover:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500 relative z-50"
          style={{ pointerEvents: 'auto' }}
        />
        
        {/* Provider-specific instructions */}
        {newEmailForm.provider === 'gmail' && (
          <div className="mt-2 p-2 rounded bg-green-500/10 border border-green-500/30 text-xs">
            <div className="font-semibold text-green-500 mb-1">📧 Gmail Setup:</div>
            <ol className="list-decimal list-inside space-y-0.5 text-muted-foreground">
              <li>Go to <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noopener noreferrer" className="text-green-400 hover:underline">Google App Passwords</a></li>
              <li>Select "Mail" and your device</li>
              <li>Copy the 16-character password (format: xxxx xxxx xxxx xxxx)</li>
              <li>Paste it above (remove spaces)</li>
            </ol>
          </div>
        )}
        
        {newEmailForm.provider === 'outlook' && (
          <div className="mt-2 p-2 rounded bg-blue-500/10 border border-blue-500/30 text-xs">
            <div className="font-semibold text-blue-500 mb-1">📧 Outlook Setup:</div>
            <ol className="list-decimal list-inside space-y-0.5 text-muted-foreground">
              <li>Go to <a href="https://account.microsoft.com/security" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">Microsoft Security Settings</a></li>
              <li>Enable 2-step verification if not already enabled</li>
              <li>Create an App Password under "Advanced security options"</li>
              <li>Use that password above</li>
            </ol>
          </div>
        )}
        
        {newEmailForm.provider === 'yahoo' && (
          <div className="mt-2 p-2 rounded bg-purple-500/10 border border-purple-500/30 text-xs">
            <div className="font-semibold text-purple-500 mb-1">📧 Yahoo Setup:</div>
            <ol className="list-decimal list-inside space-y-0.5 text-muted-foreground">
              <li>Go to <a href="https://login.yahoo.com/account/security" target="_blank" rel="noopener noreferrer" className="text-purple-400 hover:underline">Yahoo Account Security</a></li>
              <li>Click "Generate app password"</li>
              <li>Select "Other app" and enter "CyberGuardian"</li>
              <li>Copy the generated password and paste above</li>
            </ol>
          </div>
        )}
      </div>

      <div className="flex items-center gap-4">
        <div className="flex-1">
          <label className="block text-sm font-medium mb-2">Auto-scan every (hours)</label>
          <input
            type="number"
            value={newEmailForm.scan_interval_hours}
            onChange={(e) => setNewEmailForm({ ...newEmailForm, scan_interval_hours: parseInt(e.target.value) })}
            min="1"
            max="168"
            className="w-full px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all hover:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500 relative z-50"
            style={{ pointerEvents: 'auto' }}
          />
        </div>
        <div className="flex-1">
          <label className="block text-sm font-medium mb-2">Folders to scan</label>
          <input
            type="text"
            value={newEmailForm.folders_to_scan}
            onChange={(e) => setNewEmailForm({ ...newEmailForm, folders_to_scan: e.target.value })}
            placeholder="INBOX"
            className="w-full px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all hover:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500 relative z-50"
            style={{ pointerEvents: 'auto' }}
          />
        </div>
      </div>

      <button
        onClick={handleAddEmailAccount}
        disabled={isAddingEmail || !newEmailForm.email_address || !newEmailForm.password || !newEmailForm.provider}
        className="w-full px-4 py-2 rounded-lg bg-blue-500 text-white hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-blue-500/50 flex items-center justify-center gap-2 relative z-50"
        style={{ pointerEvents: 'auto' }}
      >
        {isAddingEmail ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            Testing connection...
          </>
        ) : (
          <>
            <Check className="h-4 w-4" />
            Add Account
          </>
        )}
      </button>
    </div>
  )}
              </div>
            </div>

            {/* Right Column - Info */}
            <div className="space-y-6">
              {/* System Info */}
              {systemInfo && (
                <div className="card-premium p-6 transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/20">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Info className="h-5 w-5 text-blue-500" />
                    System Information
                  </h3>

                  <div className="space-y-3 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Operating System</span>
                      <span className="font-medium">{systemInfo.os}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Hostname</span>
                      <span className="font-medium">{systemInfo.hostname}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Python Version</span>
                      <span className="font-medium">{systemInfo.python_version}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">CPU Cores</span>
                      <span className="font-medium">{systemInfo.cpu_count}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Total Memory</span>
                      <span className="font-medium">{systemInfo.total_memory_gb} GB</span>
                    </div>
                  </div>
                </div>
              )}

              {/* License Info */}
              {licenseInfo && (
                <div className="card-premium p-6 transition-all duration-300 hover:shadow-lg hover:shadow-green-500/20">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Key className="h-5 w-5 text-green-500" />
                    License Information
                  </h3>

                  <div className="flex justify-between items-start">
                  <span className="text-muted-foreground">License Key</span>
                  <span className="font-mono text-xs text-cyan-400 break-all text-right max-w-xs">
                  {localStorage.getItem('license_key') || 'N/A'}
                  </span>
              </div>


                  <div className="space-y-3 text-sm mb-4">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">License Type</span>
                      <span className="font-medium text-green-500">{licenseInfo.license_type}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Status</span>
                      <span className="badge badge--ok capitalize">{licenseInfo.status}</span>
                    </div>
                    {licenseInfo.expires_at && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Expires</span>
                        <span className="font-medium">{new Date(licenseInfo.expires_at).toLocaleDateString()}</span>
                      </div>
                    )}
                  </div>

                  <div>
                    <div className="text-sm font-medium mb-2">Features</div>
                    <div className="space-y-1">
                      {licenseInfo.features.map((feature, index) => (
                        <div key={index} className="flex items-center gap-2 text-sm text-muted-foreground">
                          <Check className="h-4 w-4 text-green-500" />
                          {feature}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
        {/* Export/Import Configuration */}
        <div className="section">
          <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
            <FileJson className="h-6 w-6 text-purple-500" />
            Configuration Backup
          </h2>
          <ExportImportConfig />
        </div>
      </main>
      </ProtectedRoute>
    );
  }