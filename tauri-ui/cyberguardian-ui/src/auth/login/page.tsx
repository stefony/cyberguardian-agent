

import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { openUrl } from '@tauri-apps/plugin-opener';


export default function LoginPage() {
  const [licenseKey, setLicenseKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
const navigate = useNavigate();

const handleActivate = async (e: React.FormEvent) => {
  e.preventDefault();
  setError('');
  setLoading(true);

  // Validate format
  const keyPattern = /^CG-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{8}$/;
  if (!keyPattern.test(licenseKey)) {
    setError('Invalid license key format. Expected: CG-XXXX-XXXX-XXXX-XXXX-XXXXXXXX');
    setLoading(false);
    return;
  }

  try {
    // 🔍 Логваме origin и userAgent, за да видим как изглеждат в Tauri build
    const deviceId = `web-${navigator.userAgent.substring(0, 20).replace(/\s/g, '-')}`;
    console.log('🔵 Activating license...', {
      licenseKey,
      deviceId,
      origin: window.location.origin,
      hostname: window.location.hostname,
    });

    const response = await fetch(
      'https://cyberguardian-backend-production.up.railway.app/api/license/activate',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          license_key: licenseKey,
          device_id: deviceId,
          hostname: window.location.hostname,
        }),
      }
    );

    console.log('🔵 Response status:', response.status);

    // Четем суровия текст, за да не хвърля JSON parse грешка
    const rawText = await response.text();
    console.log('🔵 Raw response body:', rawText);

    let data: any = {};
    try {
      data = rawText ? JSON.parse(rawText) : {};
    } catch (jsonErr) {
      console.error('⚠️ JSON parse error:', jsonErr);
      data = { raw: rawText };
    }

    console.log('🔵 Parsed data:', data);

    if (response.ok && data.success) {
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('license_key', licenseKey);
      localStorage.setItem('license_plan', data.plan);
      localStorage.setItem('license_expires', data.expires_at);
      navigate('/dashboard');
    } else {
      const msg =
        data.detail ||
        data.message ||
        `License activation failed (status ${response.status})`;
      console.error('🔴 Activation failed:', msg);
      setError(msg);
      setLoading(false);
    }
  } catch (err: any) {
    console.error('🔴 Activation error (catch):', err);
    setError(
      `License activation failed. Error: ${
        err?.message || String(err)
      }`
    );
    setLoading(false);
  }
};


  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      <div className="max-w-md w-full space-y-8 p-8 bg-white/10 backdrop-blur-lg rounded-2xl shadow-2xl">
        {/* Header */}
        <div className="text-center">
          <div className="mx-auto h-16 w-16 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-xl flex items-center justify-center mb-4">
            <svg className="h-10 w-10 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="text-3xl font-bold text-white">CyberGuardian XDR</h2>
          <p className="mt-2 text-sm text-gray-300">Activate your license key</p>
        </div>

        {/* Form */}
        <form onSubmit={handleActivate} className="mt-8 space-y-6">
          <div>
            <label htmlFor="license-key" className="block text-sm font-medium text-gray-200 mb-2">
              License Key
            </label>
            <input
              id="license-key"
              name="license-key"
              type="text"
              required
              value={licenseKey}
              onChange={(e) => setLicenseKey(e.target.value.toUpperCase())}
              placeholder="CG-XXXX-XXXX-XXXX-XXXX-XXXXXXXX"
              pattern="CG-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{8}"
              className="appearance-none relative block w-full px-4 py-3 border border-gray-600 placeholder-gray-400 text-white bg-gray-800/50 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent focus:z-10 sm:text-sm font-mono"
            />
            <p className="mt-2 text-xs text-gray-400">
            Enter your license key (31 characters)
            </p>
          </div>

          {error && (
            <div className="rounded-lg bg-red-500/10 border border-red-500/50 p-4">
              <p className="text-sm text-red-400">{error}</p>
            </div>
          )}

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-medium rounded-lg text-white bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
            >
              {loading ? (
                <span className="flex items-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Activating...
                </span>
              ) : (
                'Activate License'
              )}
            </button>
          </div>

          {/* Links */}
       {/* Links */}
<div className="text-center">
  <p className="text-sm text-gray-300">
    Don't have a license key?{' '}
    <button
  type="button"
  onClick={async () => {
    try {
      await openUrl('https://cyberguardian-dashboard.vercel.app/pricing');
    } catch (error) {
      console.error('Failed to open URL:', error);
    }
  }}
  className="font-medium text-cyan-400 hover:text-cyan-300 cursor-pointer underline"
>
  Buy Now
</button>

  </p>
</div>
        </form>
      </div>
    </div>
  );
}
