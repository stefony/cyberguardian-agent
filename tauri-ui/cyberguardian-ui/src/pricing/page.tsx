

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Check, ArrowLeft } from 'lucide-react';


export default function PricingPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState<string | null>(null);

  const plans = {
  home: {
    name: 'Home',
    price: 50,
    devices: 1,
    popular: false,  // ← ДОБАВИ ТОВА
    features: [
      'Real-time threat detection',
      '9 honeypot types',
      'Web dashboard access',
      'MITRE ATT&CK mapping',
      '1 device license',
      'Email alerts',
      'Basic support'
    ]
  },
  business: {
    name: 'Business',
    price: 100,
    devices: 5,
    popular: true,
    features: [
      'Everything in Home',
      '5 device licenses',
      'Priority support',
      'Advanced analytics',
      'Custom rules',
      'API access',
      'Team management'
    ]
  }
};

const handleCheckout = async (plan: 'home' | 'business') => {
  setLoading(plan);
  
  try {
    const API_BASE_URL = 'https://cyberguardian-backend-production.up.railway.app';
    const response = await fetch(`${API_BASE_URL}/api/stripe/checkout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plan })
    });

    const data = await response.json();
    
    if (data.url) {
      window.location.href = data.url;
    }
  } catch (error) {
    console.error('Checkout error:', error);
    alert('Payment failed. Please try again.');
    setLoading(null);
  }
};
  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-8">
      {/* Back button */}
      <button
        onClick={() => navigate('/auth/login')}
        className="flex items-center gap-2 text-slate-400 hover:text-cyan-400 transition-colors mb-8"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Login
      </button>

      {/* Hero */}
      <div className="max-w-6xl mx-auto text-center mb-12">
        <div className="flex items-center justify-center mb-4">
          <Shield className="h-12 w-12 text-cyan-400" />
        </div>
        <h1 className="text-4xl md:text-5xl font-bold text-white mb-4">
          Choose Your <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-400">Protection Plan</span>
        </h1>
        <p className="text-slate-300 text-lg">
          Professional cybersecurity for your devices
        </p>
      </div>

      {/* Plans */}
      <div className="max-w-6xl mx-auto grid md:grid-cols-2 gap-8">
        {Object.entries(plans).map(([key, plan]) => (
          <div
            key={key}
            className={`relative rounded-2xl p-8 ${
              plan.popular
                ? 'bg-gradient-to-br from-purple-900/50 to-cyan-900/50 border-2 border-cyan-400'
                : 'bg-slate-800/50 border border-slate-700'
            } backdrop-blur-xl`}
          >
            {plan.popular && (
              <div className="absolute -top-4 left-1/2 -translate-x-1/2 bg-gradient-to-r from-cyan-400 to-purple-400 text-slate-900 px-4 py-1 rounded-full text-sm font-bold">
                MOST POPULAR
              </div>
            )}

            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold text-white mb-2">{plan.name}</h2>
              <div className="flex items-baseline justify-center gap-2 mb-4">
                <span className="text-5xl font-bold text-cyan-400">€{plan.price}</span>
                <span className="text-slate-400">/year</span>
              </div>
              <p className="text-slate-400">{plan.devices} device{plan.devices > 1 ? 's' : ''}</p>
            </div>

            <ul className="space-y-4 mb-8">
              {plan.features.map((feature, i) => (
                <li key={i} className="flex items-start gap-3 text-slate-300">
                  <Check className="h-5 w-5 text-green-400 flex-shrink-0 mt-0.5" />
                  <span>{feature}</span>
                </li>
              ))}
            </ul>

            <button
              onClick={() => handleCheckout(key as 'home' | 'business')}
              disabled={loading !== null}
              className={`w-full py-4 rounded-xl font-semibold transition-all ${
                plan.popular
                  ? 'bg-gradient-to-r from-cyan-400 to-purple-400 text-slate-900 hover:shadow-lg hover:shadow-cyan-400/50'
                  : 'bg-slate-700 text-white hover:bg-slate-600'
              } disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              {loading === key ? 'Processing...' : 'Buy Now'}
            </button>
          </div>
        ))}
      </div>

      {/* Trust badges */}
      <div className="max-w-6xl mx-auto mt-12 text-center">
        <p className="text-slate-400 text-sm mb-4">Trusted by security professionals</p>
        <div className="flex items-center justify-center gap-8 text-slate-500">
          <span>✓ Secure Checkout</span>
          <span>✓ Instant Activation</span>
          <span>✓ 30-Day Money Back</span>
        </div>
      </div>
    </main>
  );
}
