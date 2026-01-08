"use client";

import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import CountUp from "react-countup";
import { 
  Trash2, 
  Clock, 
  Shield, 
  AlertTriangle, 
  Save,
  Eye,
  Play,
  Zap,
  Check
} from "lucide-react";
import { quarantineApi } from "@/lib/api";

interface AutoPurgeSettingsProps {
  onSettingsChanged?: () => void;
}

export default function AutoPurgeSettings({ onSettingsChanged }: AutoPurgeSettingsProps) {
  const [settings, setSettings] = useState({
    enabled: false,
    days_threshold: 30,
    auto_purge_critical: false,
    auto_purge_high: false,
    auto_purge_medium: true,
    auto_purge_low: true,
  });

  const [preview, setPreview] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const [executing, setExecuting] = useState(false);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const res = await quarantineApi.getAutoPurgeSettings();
      if (res.success && res.data) {
        setSettings(res.data);
      }
    } catch (err) {
      console.error("Error loading settings:", err);
    }
    setLoading(false);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await quarantineApi.updateAutoPurgeSettings(settings);
      if (res.success) {
        alert("✅ Auto-purge settings saved successfully!");
        if (onSettingsChanged) onSettingsChanged();
      } else {
        alert(`❌ Failed to save: ${res.error}`);
      }
    } catch (err) {
      console.error("Error saving settings:", err);
      alert("❌ Error saving settings");
    }
    setSaving(false);
  };

  const handlePreview = async () => {
    setPreviewing(true);
    try {
      const res = await quarantineApi.previewAutoPurge();
      if (res.success && res.data) {
        setPreview(res.data);
      } else {
        alert(`❌ Failed to preview: ${res.error}`);
      }
    } catch (err) {
      console.error("Error previewing:", err);
      alert("❌ Error loading preview");
    }
    setPreviewing(false);
  };

  const handleExecute = async () => {
    if (!settings.enabled) {
      alert("⚠️ Auto-purge is disabled. Enable it first!");
      return;
    }

    if (!confirm("⚠️ Execute auto-purge now? This will permanently delete old files!")) {
      return;
    }

    setExecuting(true);
    try {
      const res = await quarantineApi.executeAutoPurge();
      if (res.success && res.data) {
        alert(`✅ Auto-purge completed!\n\nDeleted: ${res.data.deleted_count} files\nFreed: ${formatBytes(res.data.deleted_size_bytes)}`);
        setPreview(null);
        if (onSettingsChanged) onSettingsChanged();
      } else {
        alert(`❌ Failed to execute: ${res.error}`);
      }
    } catch (err) {
      console.error("Error executing:", err);
      alert("❌ Error executing auto-purge");
    }
    setExecuting(false);
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + " " + sizes[i];
  };

  // Loading Skeleton
  if (loading) {
    return (
      <div className="card-premium p-6">
        <div className="animate-pulse space-y-6">
          {/* Header skeleton */}
          <div className="flex items-center justify-between">
            <div className="space-y-2">
              <div className="h-6 w-48 bg-muted/30 rounded"></div>
              <div className="h-4 w-64 bg-muted/20 rounded"></div>
            </div>
            <div className="h-8 w-32 bg-muted/30 rounded-full"></div>
          </div>

          {/* Slider skeleton */}
          <div className="space-y-3">
            <div className="h-4 w-40 bg-muted/20 rounded"></div>
            <div className="h-3 w-full bg-muted/30 rounded-full"></div>
          </div>

          {/* Cards skeleton */}
          <div className="grid grid-cols-2 gap-3">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-20 bg-muted/20 rounded-lg"></div>
            ))}
          </div>

          {/* Buttons skeleton */}
          <div className="flex gap-3">
            <div className="flex-1 h-12 bg-muted/30 rounded-lg"></div>
            <div className="h-12 w-32 bg-muted/30 rounded-lg"></div>
            <div className="h-12 w-32 bg-muted/30 rounded-lg"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="card-premium p-6 space-y-6 hover:shadow-xl transition-shadow duration-300"
      style={{ pointerEvents: 'auto', position: 'relative', zIndex: 10 }}
    >
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
        className="flex items-center justify-between"
      >
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <motion.div
              animate={{ rotate: [0, 10, -10, 0] }}
              transition={{ duration: 2, repeat: Infinity, repeatDelay: 3 }}
            >
              <Zap className="h-5 w-5 text-yellow-500" />
            </motion.div>
            Auto-Purge Policy
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            Automatically delete old quarantined files
          </p>
        </div>

        {/* Enhanced Toggle Switch */}
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={() => setSettings({ ...settings, enabled: !settings.enabled })}
          className="relative inline-flex items-center cursor-pointer group"
          style={{ pointerEvents: 'auto', zIndex: 20 }}
        >
          <motion.div
            animate={{
              backgroundColor: settings.enabled ? "#9333ea" : "#374151",
            }}
            transition={{ duration: 0.3 }}
            className="w-14 h-7 rounded-full relative shadow-lg group-hover:shadow-xl transition-shadow"
          >
            {/* Glow effect */}
            {settings.enabled && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="absolute inset-0 rounded-full bg-purple-500/30 blur-md"
              />
            )}
            
            {/* Thumb */}
            <motion.div
              animate={{
                x: settings.enabled ? 28 : 2,
              }}
              transition={{ type: "spring", stiffness: 500, damping: 30 }}
              className="absolute top-0.5 bg-white rounded-full h-6 w-6 shadow-md"
            >
              {/* Check icon when enabled */}
              <AnimatePresence>
                {settings.enabled && (
                  <motion.div
                    initial={{ scale: 0, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 0, opacity: 0 }}
                    className="absolute inset-0 flex items-center justify-center"
                  >
                    <Check className="h-3 w-3 text-purple-600" />
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          </motion.div>
          
          <motion.span
            animate={{
              color: settings.enabled ? "#a855f7" : "#9ca3af",
            }}
            className="ml-3 text-sm font-medium"
          >
            {settings.enabled ? "Enabled" : "Disabled"}
          </motion.span>
        </motion.button>
      </motion.div>

      {/* Days Threshold Slider */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.2 }}
        className="space-y-3"
      >
        <div className="flex items-center justify-between">
          <label className="text-sm font-medium flex items-center gap-2">
            <Clock className="h-4 w-4 text-blue-400" />
            Delete files older than:
          </label>
          <motion.span
            key={settings.days_threshold}
            initial={{ scale: 1.2, color: "#a855f7" }}
            animate={{ scale: 1, color: "#a855f7" }}
            className="text-2xl font-bold"
          >
            <CountUp end={settings.days_threshold} duration={0.5} /> days
          </motion.span>
        </div>

        <div className="relative group" style={{ pointerEvents: 'auto', zIndex: 20 }}>
          <input
            type="range"
            min="1"
            max="90"
            value={settings.days_threshold}
            onChange={(e) => setSettings({ ...settings, days_threshold: parseInt(e.target.value) })}
            className="slider-thumb w-full h-3 rounded-lg appearance-none cursor-pointer transition-all duration-300 group-hover:h-4"
            style={{
              background: `linear-gradient(to right, #a855f7 0%, #a855f7 ${((settings.days_threshold - 1) / 89) * 100}%, #374151 ${((settings.days_threshold - 1) / 89) * 100}%, #374151 100%)`,
              pointerEvents: 'auto',
            }}
          />
          {/* Glow effect on hover */}
          <div className="absolute inset-0 rounded-lg bg-purple-500/0 group-hover:bg-purple-500/10 transition-colors duration-300 pointer-events-none" />
        </div>

        <div className="flex justify-between text-xs text-muted-foreground">
          <span>1 day</span>
          <span>30 days</span>
          <span>90 days</span>
        </div>
      </motion.div>

      {/* Threat Level Toggles */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.3 }}
        className="space-y-3"
      >
        <label className="text-sm font-medium flex items-center gap-2">
          <Shield className="h-4 w-4 text-green-400" />
          Auto-purge by threat level:
        </label>

        <div className="grid grid-cols-2 gap-3">
          {/* Critical */}
          <motion.button
            whileHover={{ scale: 1.02, y: -2 }}
            whileTap={{ scale: 0.98 }}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              setSettings({ ...settings, auto_purge_critical: !settings.auto_purge_critical });
            }}
            type="button"
            style={{ pointerEvents: 'auto', zIndex: 20 }}
            className="flex items-center gap-3 p-3 rounded-lg bg-red-500/10 border-2 border-red-500/30 hover:bg-red-500/20 hover:border-red-500/50 transition-all duration-300 cursor-pointer text-left group hover:shadow-lg hover:shadow-red-500/20"
          >
            <motion.div
              animate={{
                backgroundColor: settings.auto_purge_critical ? "#ef4444" : "#1f2937",
                borderColor: settings.auto_purge_critical ? "#ef4444" : "#4b5563",
              }}
              className="w-5 h-5 rounded border-2 flex items-center justify-center"
            >
              <AnimatePresence>
                {settings.auto_purge_critical && (
                  <motion.svg
                    initial={{ scale: 0, rotate: -180 }}
                    animate={{ scale: 1, rotate: 0 }}
                    exit={{ scale: 0, rotate: 180 }}
                    transition={{ type: "spring", stiffness: 500, damping: 25 }}
                    className="w-3 h-3 text-white"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M5 13l4 4L19 7"></path>
                  </motion.svg>
                )}
              </AnimatePresence>
            </motion.div>
            <div className="flex-1">
              <div className="font-medium text-red-400 group-hover:text-red-300 transition-colors">Critical</div>
              <div className="text-xs text-muted-foreground">Highest risk</div>
            </div>
          </motion.button>

          {/* High */}
          <motion.button
            whileHover={{ scale: 1.02, y: -2 }}
            whileTap={{ scale: 0.98 }}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              setSettings({ ...settings, auto_purge_high: !settings.auto_purge_high });
            }}
            type="button"
            style={{ pointerEvents: 'auto', zIndex: 20 }}
            className="flex items-center gap-3 p-3 rounded-lg bg-orange-500/10 border-2 border-orange-500/30 hover:bg-orange-500/20 hover:border-orange-500/50 transition-all duration-300 cursor-pointer text-left group hover:shadow-lg hover:shadow-orange-500/20"
          >
            <motion.div
              animate={{
                backgroundColor: settings.auto_purge_high ? "#f97316" : "#1f2937",
                borderColor: settings.auto_purge_high ? "#f97316" : "#4b5563",
              }}
              className="w-5 h-5 rounded border-2 flex items-center justify-center"
            >
              <AnimatePresence>
                {settings.auto_purge_high && (
                  <motion.svg
                    initial={{ scale: 0, rotate: -180 }}
                    animate={{ scale: 1, rotate: 0 }}
                    exit={{ scale: 0, rotate: 180 }}
                    transition={{ type: "spring", stiffness: 500, damping: 25 }}
                    className="w-3 h-3 text-white"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M5 13l4 4L19 7"></path>
                  </motion.svg>
                )}
              </AnimatePresence>
            </motion.div>
            <div className="flex-1">
              <div className="font-medium text-orange-400 group-hover:text-orange-300 transition-colors">High</div>
              <div className="text-xs text-muted-foreground">High risk</div>
            </div>
          </motion.button>

          {/* Medium */}
          <motion.button
            whileHover={{ scale: 1.02, y: -2 }}
            whileTap={{ scale: 0.98 }}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              setSettings({ ...settings, auto_purge_medium: !settings.auto_purge_medium });
            }}
            type="button"
            style={{ pointerEvents: 'auto', zIndex: 20 }}
            className="flex items-center gap-3 p-3 rounded-lg bg-yellow-500/10 border-2 border-yellow-500/30 hover:bg-yellow-500/20 hover:border-yellow-500/50 transition-all duration-300 cursor-pointer text-left group hover:shadow-lg hover:shadow-yellow-500/20"
          >
            <motion.div
              animate={{
                backgroundColor: settings.auto_purge_medium ? "#eab308" : "#1f2937",
                borderColor: settings.auto_purge_medium ? "#eab308" : "#4b5563",
              }}
              className="w-5 h-5 rounded border-2 flex items-center justify-center"
            >
              <AnimatePresence>
                {settings.auto_purge_medium && (
                  <motion.svg
                    initial={{ scale: 0, rotate: -180 }}
                    animate={{ scale: 1, rotate: 0 }}
                    exit={{ scale: 0, rotate: 180 }}
                    transition={{ type: "spring", stiffness: 500, damping: 25 }}
                    className="w-3 h-3 text-white"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M5 13l4 4L19 7"></path>
                  </motion.svg>
                )}
              </AnimatePresence>
            </motion.div>
            <div className="flex-1">
              <div className="font-medium text-yellow-400 group-hover:text-yellow-300 transition-colors">Medium</div>
              <div className="text-xs text-muted-foreground">Moderate risk</div>
            </div>
          </motion.button>

          {/* Low */}
          <motion.button
            whileHover={{ scale: 1.02, y: -2 }}
            whileTap={{ scale: 0.98 }}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              setSettings({ ...settings, auto_purge_low: !settings.auto_purge_low });
            }}
            type="button"
            style={{ pointerEvents: 'auto', zIndex: 20 }}
            className="flex items-center gap-3 p-3 rounded-lg bg-green-500/10 border-2 border-green-500/30 hover:bg-green-500/20 hover:border-green-500/50 transition-all duration-300 cursor-pointer text-left group hover:shadow-lg hover:shadow-green-500/20"
          >
            <motion.div
              animate={{
                backgroundColor: settings.auto_purge_low ? "#22c55e" : "#1f2937",
                borderColor: settings.auto_purge_low ? "#22c55e" : "#4b5563",
              }}
              className="w-5 h-5 rounded border-2 flex items-center justify-center"
            >
              <AnimatePresence>
                {settings.auto_purge_low && (
                  <motion.svg
                    initial={{ scale: 0, rotate: -180 }}
                    animate={{ scale: 1, rotate: 0 }}
                    exit={{ scale: 0, rotate: 180 }}
                    transition={{ type: "spring", stiffness: 500, damping: 25 }}
                    className="w-3 h-3 text-white"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M5 13l4 4L19 7"></path>
                  </motion.svg>
                )}
              </AnimatePresence>
            </motion.div>
            <div className="flex-1">
              <div className="font-medium text-green-400 group-hover:text-green-300 transition-colors">Low</div>
              <div className="text-xs text-muted-foreground">Low risk</div>
            </div>
          </motion.button>
        </div>
      </motion.div>

      {/* Preview Section with Animation */}
      <AnimatePresence>
        {preview && (
          <motion.div
            initial={{ opacity: 0, height: 0, y: -20 }}
            animate={{ opacity: 1, height: "auto", y: 0 }}
            exit={{ opacity: 0, height: 0, y: -20 }}
            transition={{ duration: 0.4 }}
            className="overflow-hidden"
          >
            <div className="p-4 rounded-lg bg-blue-500/10 border-2 border-blue-500/30 space-y-2 shadow-lg shadow-blue-500/10">
              <div className="flex items-center gap-2 text-blue-400 font-medium">
                <Eye className="h-4 w-4" />
                Preview Results
              </div>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <div className="text-muted-foreground">Files to delete:</div>
                  <div className="text-xl font-bold text-blue-400">
                    <CountUp end={preview.total_count} duration={1.5} />
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Space to free:</div>
                  <div className="text-xl font-bold text-blue-400">{formatBytes(preview.total_size_bytes)}</div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Action Buttons */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.4 }}
        className="flex gap-3"
      >
        <motion.button
          whileHover={{ scale: 1.02, y: -2 }}
          whileTap={{ scale: 0.98 }}
          onClick={handleSave}
          disabled={saving}
          style={{ pointerEvents: 'auto', zIndex: 20 }}
          className="flex-1 px-4 py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white font-medium rounded-lg transition-all duration-300 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-xl hover:shadow-purple-500/30"
        >
          <Save className={`h-4 w-4 ${saving ? "animate-spin" : ""}`} />
          {saving ? "Saving..." : "Save Settings"}
        </motion.button>

        <motion.button
          whileHover={{ scale: 1.05, y: -2 }}
          whileTap={{ scale: 0.95 }}
          onClick={handlePreview}
          disabled={previewing}
          style={{ pointerEvents: 'auto', zIndex: 20 }}
          className="px-4 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-all duration-300 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-xl hover:shadow-blue-500/30"
        >
          <Eye className={`h-4 w-4 ${previewing ? "animate-spin" : ""}`} />
          {previewing ? "Loading..." : "Preview"}
        </motion.button>

        <motion.button
          whileHover={{ scale: 1.05, y: -2 }}
          whileTap={{ scale: 0.95 }}
          onClick={handleExecute}
          disabled={!settings.enabled || executing}
          style={{ pointerEvents: 'auto', zIndex: 20 }}
          className="px-4 py-3 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-all duration-300 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-xl hover:shadow-red-500/30"
        >
          <Play className={`h-4 w-4 ${executing ? "animate-spin" : ""}`} />
          {executing ? "Running..." : "Execute Now"}
        </motion.button>
      </motion.div>

      {/* Warning with Pulse Animation */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.5 }}
        className="relative overflow-hidden rounded-lg"
      >
        <motion.div
          animate={{ opacity: [0.5, 1, 0.5] }}
          transition={{ duration: 2, repeat: Infinity }}
          className="absolute inset-0 bg-yellow-500/5"
        />
        <div className="relative flex items-start gap-3 p-4 bg-yellow-500/10 border-2 border-yellow-500/30 rounded-lg">
          <motion.div
            animate={{ rotate: [0, 10, -10, 0] }}
            transition={{ duration: 0.5, repeat: Infinity, repeatDelay: 2 }}
          >
            <AlertTriangle className="h-5 w-5 text-yellow-500 flex-shrink-0 mt-0.5" />
          </motion.div>
          <div className="text-sm text-yellow-200/90">
            <div className="font-medium mb-1">Warning</div>
            Auto-purge permanently deletes files. Make sure you understand the policy before enabling it.
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}