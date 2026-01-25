import { useNavigate, useSearchParams } from 'react-router-dom';
import { useEffect, useState, Suspense } from 'react';
import { CheckCircle, Mail, ArrowRight } from 'lucide-react';

function SuccessContent() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const sessionId = searchParams.get('session_id');
  const [countdown, setCountdown] = useState(10);

  useEffect(() => {
    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          navigate('/auth/login');
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [navigate]);

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center p-8">
      <div className="max-w-2xl w-full bg-slate-800/50 backdrop-blur-xl border border-slate-700 rounded-2xl p-12 text-center">
        {/* Success icon */}
        <div className="w-20 h-20 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
          <CheckCircle className="w-12 h-12 text-green-400" />
        </div>

        <h1 className="text-4xl font-bold text-white mb-4">
          Payment Successful! 🎉
        </h1>

        <p className="text-slate-300 text-lg mb-8">
          Your CyberGuardian license has been activated.
        </p>

        {/* Email instruction */}
        <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-6 mb-8">
          <div className="flex items-center justify-center mb-4">
            <Mail className="w-8 h-8 text-blue-400" />
          </div>
          <h2 className="text-xl font-bold text-white mb-2">
            Check Your Email
          </h2>
          <p className="text-slate-300">
            We've sent your license key to your email address.
            <br />
            Copy the key and activate your account.
          </p>
        </div>

        {/* Instructions */}
        <div className="text-left bg-slate-800/50 rounded-lg p-6 mb-8">
          <h3 className="text-lg font-bold text-white mb-4">Next Steps:</h3>
          <ol className="space-y-3 text-slate-300">
            <li className="flex items-start">
              <span className="text-cyan-400 font-bold mr-3">1.</span>
              Check your email inbox
            </li>
            <li className="flex items-start">
              <span className="text-cyan-400 font-bold mr-3">2.</span>
              Copy your license key (CG-XXXX-XXXX...)
            </li>
            <li className="flex items-start">
              <span className="text-cyan-400 font-bold mr-3">3.</span>
              Return to the login page
            </li>
            <li className="flex items-start">
              <span className="text-cyan-400 font-bold mr-3">4.</span>
              Enter your license key and activate
            </li>
          </ol>
        </div>

        {/* Auto-redirect notice */}
        <p className="text-slate-400 text-sm mb-6">
          Redirecting to login in {countdown} seconds...
        </p>

        {/* Manual button */}
        <button
          onClick={() => navigate('/auth/login')}
          className="bg-gradient-to-r from-cyan-400 to-purple-400 text-slate-900 px-8 py-4 rounded-xl font-semibold hover:shadow-lg hover:shadow-cyan-400/50 transition-all flex items-center gap-2 mx-auto"
        >
          Go to Login Now
          <ArrowRight className="h-5 w-5" />
        </button>

        {/* Session ID (for debugging) */}
        {sessionId && (
          <p className="text-slate-600 text-xs mt-8">
            Session ID: {sessionId}
          </p>
        )}
      </div>
    </main>
  );
}

export default function SuccessPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center">
        <div className="text-white">Loading...</div>
      </div>
    }>
      <SuccessContent />
    </Suspense>
  );
}