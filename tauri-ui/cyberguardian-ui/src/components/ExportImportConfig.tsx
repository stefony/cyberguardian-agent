"use client";

import { useState } from "react";
import { Download, Upload, FileJson, AlertCircle, CheckCircle, XCircle } from "lucide-react";
import { settingsApi } from "@/lib/api";

export default function ExportImportConfig() {
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState<any>(null);

  const handleExport = async () => {
    setExporting(true);
    try {
      const res = await settingsApi.exportConfig();
      
      if (res.success && res.data) {
        // Create JSON file and download
        const jsonString = JSON.stringify(res.data, null, 2);
        const blob = new Blob([jsonString], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = res.data.filename || 'cyberguardian-config.json';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        
        alert('✅ Configuration exported successfully!');
      } else {
        alert(`❌ Export failed: ${res.error}`);
      }
    } catch (err) {
      console.error('Export error:', err);
      alert('❌ Error exporting configuration');
    }
    setExporting(false);
  };

  const handleImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setImporting(true);
    setImportResult(null);

    try {
      // Read file content
      const fileContent = await file.text();
      const config = JSON.parse(fileContent);

      // Validate basic structure
      if (!config.version) {
        alert('⚠️ Invalid config file: missing version');
        setImporting(false);
        return;
      }

      // Import configuration
      const res = await settingsApi.importConfig(config);
      
      if (res.success && res.data) {
        setImportResult(res.data);
        
        if (res.data.success) {
          alert(`✅ ${res.data.message}`);
        } else {
          alert(`⚠️ ${res.data.message}`);
        }
      } else {
        alert(`❌ Import failed: ${res.error}`);
      }
    } catch (err) {
      console.error('Import error:', err);
      alert('❌ Error importing configuration. Please check the file format.');
    }
    
    setImporting(false);
    
    // Reset input
    event.target.value = '';
  };

  return (
    <div className="space-y-6">
      {/* Export/Import Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Export Card */}
        <div 
          className="card-premium p-6 space-y-4"
          style={{ pointerEvents: 'auto', position: 'relative', zIndex: 10 }}
        >
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-lg bg-blue-500/10 border-2 border-blue-500/30">
              <Download className="h-6 w-6 text-blue-400" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-foreground">Export Configuration</h3>
              <p className="text-sm text-muted-foreground">Download all settings as JSON</p>
            </div>
          </div>

          <div className="space-y-2 text-sm text-muted-foreground">
            <p>✅ App settings & preferences</p>
            <p>✅ Protection & security rules</p>
            <p>✅ Exclusions & scan schedules</p>
            <p>✅ Auto-purge policy</p>
          </div>

         <button
            onClick={handleExport}
            disabled={exporting}
            style={{ pointerEvents: 'auto', zIndex: 20, position: 'relative' }}
            className="w-full px-4 py-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-medium rounded-lg transition-all duration-200 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <FileJson className={`h-4 w-4 ${exporting ? "animate-spin" : ""}`} />
            {exporting ? "Exporting..." : "Export Config"}
          </button>
        </div>

        {/* Import Card */}
        <div 
          className="card-premium p-6 space-y-4"
          style={{ pointerEvents: 'auto', position: 'relative', zIndex: 10 }}
        >
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-lg bg-green-500/10 border-2 border-green-500/30">
              <Upload className="h-6 w-6 text-green-400" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-foreground">Import Configuration</h3>
              <p className="text-sm text-muted-foreground">Restore settings from JSON file</p>
            </div>
          </div>

          <div className="space-y-2 text-sm text-muted-foreground">
            <p>📥 Upload exported config file</p>
            <p>🔄 Restore all settings</p>
            <p>⚡ Quick system setup</p>
            <p>🔒 Backup & recovery</p>
          </div>

       <label 
            className="w-full px-4 py-3 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white font-medium rounded-lg transition-all duration-200 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ pointerEvents: 'auto', zIndex: 20, position: 'relative' }}
          >
            <Upload className={`h-4 w-4 ${importing ? "animate-spin" : ""}`} />
            {importing ? "Importing..." : "Import Config"}
            <input
              type="file"
              accept=".json"
              onChange={handleImport}
              disabled={importing}
              className="hidden"
              style={{ pointerEvents: 'auto' }}
            />
          </label>
        </div>
      </div>

      {/* Import Results */}
      {importResult && (
        <div 
          className="card-premium p-6 space-y-4"
          style={{ pointerEvents: 'auto', position: 'relative', zIndex: 10 }}
        >
          <h3 className="text-lg font-bold flex items-center gap-2">
            {importResult.success ? (
              <CheckCircle className="h-5 w-5 text-green-500" />
            ) : (
              <AlertCircle className="h-5 w-5 text-yellow-500" />
            )}
            Import Results
          </h3>

          {/* Imported Items */}
          {importResult.imported && importResult.imported.length > 0 && (
            <div className="space-y-2">
              <div className="text-sm font-medium text-green-400">
                ✅ Successfully Imported ({importResult.imported.length})
              </div>
              <div className="space-y-1">
                {importResult.imported.map((item: string, idx: number) => (
                  <div key={idx} className="flex items-center gap-2 text-sm text-muted-foreground pl-4">
                    <CheckCircle className="h-3 w-3 text-green-500" />
                    {item}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Failed Items */}
          {importResult.failed && importResult.failed.length > 0 && (
            <div className="space-y-2">
              <div className="text-sm font-medium text-red-400">
                ❌ Failed to Import ({importResult.failed.length})
              </div>
              <div className="space-y-1">
                {importResult.failed.map((item: string, idx: number) => (
                  <div key={idx} className="flex items-center gap-2 text-sm text-muted-foreground pl-4">
                    <XCircle className="h-3 w-3 text-red-500" />
                    {item}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Warnings */}
          {importResult.warnings && importResult.warnings.length > 0 && (
            <div className="space-y-2">
              <div className="text-sm font-medium text-yellow-400">
                ⚠️ Warnings ({importResult.warnings.length})
              </div>
              <div className="space-y-1">
                {importResult.warnings.map((item: string, idx: number) => (
                  <div key={idx} className="flex items-center gap-2 text-sm text-muted-foreground pl-4">
                    <AlertCircle className="h-3 w-3 text-yellow-500" />
                    {item}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Info Box */}
      <div className="card-premium p-4 flex items-start gap-3 bg-blue-500/5 border-2 border-blue-500/20">
        <AlertCircle className="h-5 w-5 text-blue-400 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-blue-200/90">
          <div className="font-medium mb-1">About Export/Import</div>
          <p>
            Export creates a backup of all your settings. Import restores settings from a backup file.
            You can use this to migrate configurations between systems or create backups before making changes.
          </p>
        </div>
      </div>
    </div>
  );
}