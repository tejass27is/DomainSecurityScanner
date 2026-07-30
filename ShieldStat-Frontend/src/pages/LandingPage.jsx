// @ts-ignore
import logo from "../assets/logo.svg"
// @ts-ignore
import logoWhite from "../assets/iSecurify Logo - White - Transparent.png"
// @ts-ignore
import isecurify_logo from "../assets/isecurify_logo.png"
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useOutletContext } from "react-router-dom";
import { scanPublicDomain } from "../services/api";
import { Shield, Zap, Lock, TrendingUp, CheckCircle2, Globe } from "lucide-react";

function LandingPage() {
  const navigate = useNavigate();
  const { isDarkMode, onToggleDarkMode } = useOutletContext();

  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const progressIntervalRef = useRef(null);

  useEffect(() => {
    return () => {
      if (progressIntervalRef.current) {
        window.clearInterval(progressIntervalRef.current);
      }
    };
  }, []);

  const startProgress = () => {
    setProgress(0);
    if (progressIntervalRef.current) {
      window.clearInterval(progressIntervalRef.current);
    }
    progressIntervalRef.current = window.setInterval(() => {
      setProgress((prev) => {
        const next = prev + 10;
        return next >= 92 ? 92 : next;
      });
    }, 450);
  };

  const finishProgress = () => {
    if (progressIntervalRef.current) {
      window.clearInterval(progressIntervalRef.current);
      progressIntervalRef.current = null;
    }
    setProgress(100);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");

    const domain = event.target.domain_input_field?.value?.trim();
    if (!domain) {
      setError("Please enter a valid domain.");
      return;
    }

    setLoading(true);
    startProgress();
    try {
      await scanPublicDomain(domain);
      finishProgress();
      navigate(`/domain-overview?domain=${encodeURIComponent(domain)}`, {
        replace: true,
        state: { queued: true },
      });
    } catch (err) {
      finishProgress();
      setError(err?.message || "Unable to start scan. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className={`${isDarkMode ? 'bg-slate-900 text-white' : 'bg-white text-slate-900'} min-h-screen flex flex-col font-body transition-colors duration-300`}>
      {/* Navbar */}
      <header className={`fixed top-0 inset-x-0 z-50 ${isDarkMode ? 'bg-slate-900/95 border-slate-700' : 'bg-white/95 border-slate-200'} backdrop-blur-md border-b transition-colors duration-300`}>
        <div className="flex justify-between items-center px-8 py-4 w-full max-[344px]:px-3 max-[344px]:py-3">
          <div className="flex items-center gap-3">
            <img
              src={isDarkMode ? logoWhite : logo}
              alt="Logo"
              className="max-h-10 w-auto object-contain"
            />
          </div>

          <nav className="flex items-center gap-5 max-[520px]:gap-4">
            <button
              type="button"
              onClick={onToggleDarkMode}
              className={`inline-flex h-10 items-center gap-3 rounded-lg px-1.5 transition ${isDarkMode ? 'text-slate-400 hover:bg-slate-800' : 'text-slate-600 hover:bg-slate-100'}`}
              aria-pressed={isDarkMode}
              aria-label={isDarkMode ? "Switch to light mode" : "Switch to dark mode"}
            >
              <span className="material-symbols-outlined flex h-6 w-6 items-center justify-center text-[22px]">
                {isDarkMode ? "dark_mode" : "light_mode"}
              </span>
            </button>
            <Link to="/auth">
              <button className="text-white bg-gradient-to-r from-purple-600 to-purple-700 px-6 py-2.5 rounded-lg font-semibold shadow-lg hover:shadow-xl hover:from-purple-700 hover:to-purple-800 transition-all duration-300">
                LOGIN
              </button>
            </Link>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-grow flex flex-col">
        {/* Hero Section */}
        <section className={`pt-24 pb-16 px-6 relative overflow-hidden ${isDarkMode ? 'bg-gradient-to-b from-slate-900 to-slate-800' : 'bg-gradient-to-b from-purple-50 to-purple-100'}`}>
          {/* Background Elements */}
          <div className="absolute top-0 right-0 w-96 h-96 bg-purple-400 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse"></div>
          <div className="absolute bottom-0 left-0 w-96 h-96 bg-purple-400 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse animation-delay-2000"></div>

          <div className="relative z-10 w-full text-center">
            {/* Badge */}
            {/* <div className="inline-flex items-center gap-2 mb-6 px-4 py-2 rounded-full border border-indigo-200 dark:border-indigo-800 bg-indigo-50 dark:bg-indigo-900/30">
              <span className="w-2 h-2 bg-indigo-600 rounded-full"></span>
              <span className={`text-sm font-semibold ${isDarkMode ? 'text-indigo-300' : 'text-indigo-700'}`}>Enterprise Security Scanner</span>
            </div> */}

            {/* Logo */}
            <div className="mb-8">
              <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-br from-purple-600 to-purple-700 shadow-2xl">
                <img
                  src={isecurify_logo}
                  alt="Logo"
                  className="w-12 h-12 rounded-lg"
                />
              </div>
            </div>

            {/* Heading */}
            <h1 className={`text-5xl md:text-7xl font-extrabold tracking-tight mb-6 ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>
              Secure Your Domain
              <span className="block bg-gradient-to-r from-purple-600 to-purple-700 text-transparent bg-clip-text pb-2">
                With Intelligence
              </span>
            </h1>

            <p className={`text-xl md:text-2xl mb-10 max-w-2xl mx-auto leading-relaxed ${isDarkMode ? 'text-slate-300' : 'text-slate-600'}`}>
              Comprehensive security analysis for your domain and digital infrastructure. Detect vulnerabilities, track threats, and fortify your online presence with real-time intelligence.
            </p>

            {/* CTA - Domain Scan Input */}
            <div className="w-full mx-auto mb-12">
              <form className="relative group" onSubmit={handleSubmit}>
                <div className={`absolute -inset-1 bg-gradient-to-r from-purple-600 to-purple-700 rounded-2xl blur opacity-20 group-focus-within:opacity-100 transition duration-1000`}></div>

                <div className={`relative rounded-2xl p-2 ${isDarkMode ? 'bg-slate-800' : 'bg-white'} shadow-xl border ${isDarkMode ? 'border-slate-700' : 'border-slate-200'}`}>
                  <div className="flex flex-wrap items-center gap-3">
                    <div className={`flex items-center pl-6 ${isDarkMode ? 'text-slate-500' : 'text-slate-400'}`}>
                      <Globe size={24} />
                    </div>

                    <input
                      name="domain_input_field"
                      type="text"
                      placeholder="Enter your domain (e.g., example.com)"
                      className={`flex-1 bg-transparent outline-none px-4 py-4 text-lg font-medium ${isDarkMode ? 'placeholder:text-slate-500 text-white' : 'placeholder:text-slate-400 text-slate-900'}`}
                    />

                    <button
                      type="submit"
                      disabled={loading}
                      className={`text-white bg-gradient-to-r from-purple-600 to-purple-700 px-8 py-4 rounded-xl font-bold flex items-center gap-2 hover:shadow-lg hover:from-purple-700 hover:to-purple-800 transition-all duration-300 mr-2 ${loading ? "opacity-70 cursor-not-allowed" : ""}`}
                    >
                      <Zap size={20} />
                      {loading ? "Queueing scan..." : "Start Scan"}
                    </button>
                  </div>
                </div>
              </form>

              {error ? (
                <p className="mt-4 text-sm text-rose-600">{error}</p>
              ) : (
                <p className={`mt-4 text-sm ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>
                  No sign-up required. Get instant security insights in seconds.
                </p>
              )}

              {loading && (
                <div className="mt-6">
                  <div className="flex items-center justify-between text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                    <span>Scan progress</span>
                    <span>{progress}%</span>
                  </div>
                  <div className="h-3 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-purple-600 transition-all duration-300"
                      style={{ width: `${progress}%` }}
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Quick Stats */}
            <div className="grid grid-cols-3 gap-4 w-full mx-auto mb-8">
              <div className={`p-4 rounded-lg ${isDarkMode ? 'bg-slate-700/50 border-slate-600' : 'bg-white/50 border-slate-200'} border backdrop-blur`}>
                <div className="text-2xl font-bold text-purple-600">50K+</div>
                <div className={`text-sm ${isDarkMode ? 'text-slate-400' : 'text-slate-600'}`}>Domains Scanned</div>
              </div>
              <div className={`p-4 rounded-lg ${isDarkMode ? 'bg-slate-700/50 border-slate-600' : 'bg-white/50 border-slate-200'} border backdrop-blur`}>
                <div className="text-2xl font-bold text-purple-600">99.9%</div>
                <div className={`text-sm ${isDarkMode ? 'text-slate-400' : 'text-slate-600'}`}>Uptime SLA</div>
              </div>
              <div className={`p-4 rounded-lg ${isDarkMode ? 'bg-slate-700/50 border-slate-600' : 'bg-white/50 border-slate-200'} border backdrop-blur`}>
                <div className="text-2xl font-bold text-green-600">24/7</div>
                <div className={`text-sm ${isDarkMode ? 'text-slate-400' : 'text-slate-600'}`}>Monitoring</div>
              </div>
            </div>

            {/* Trust Badges */}
            <div className="flex flex-wrap justify-center gap-4">
              <div className="flex items-center gap-2">
                <CheckCircle2 size={20} className="text-green-600" />
                <span className={`text-sm font-medium ${isDarkMode ? 'text-slate-300' : 'text-slate-700'}`}>ISO 27001 Certified</span>
              </div>
              <div className="flex items-center gap-2">
                <Lock size={20} className="text-purple-600" />
                <span className={`text-sm font-medium ${isDarkMode ? 'text-slate-300' : 'text-slate-700'}`}>Enterprise Grade</span>
              </div>
              <div className="flex items-center gap-2">
                <Shield size={20} className="text-purple-600" />
                <span className={`text-sm font-medium ${isDarkMode ? 'text-slate-300' : 'text-slate-700'}`}>Always Updated</span>
              </div>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className={`py-20 px-6 ${isDarkMode ? 'bg-slate-800' : 'bg-slate-50'}`}>
          <div className="w-full mx-auto">
            <div className="text-center mb-16">
              <h2 className={`text-4xl md:text-5xl font-bold mb-4 ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>
                Comprehensive Security Analysis
              </h2>
              <p className={`text-xl ${isDarkMode ? 'text-slate-300' : 'text-slate-600'}`}>
                Everything you need to protect your digital infrastructure
              </p>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
              {/* Feature Cards */}
              {[
                {
                  icon: Shield,
                  title: "SSL Certificate Analysis",
                  description: "Verify certificate validity, expiration dates, and detect protocol vulnerabilities"
                },
                {
                  icon: Globe,
                  title: "DNS Integrity Check",
                  description: "Monitor DNS records for tampering, ensure proper DNSSEC configuration"
                },
                {
                  icon: TrendingUp,
                  title: "Threat Intelligence",
                  description: "Real-time threat detection powered by global security databases"
                },
                {
                  icon: Lock,
                  title: "Port Security Scan",
                  description: "Identify open ports, vulnerable services, and potential entry points"
                },
                {
                  icon: Zap,
                  title: "Malware Detection",
                  description: "Advanced scanning for malware, backdoors, and suspicious activity"
                },
                {
                  icon: CheckCircle2,
                  title: "Compliance Reports",
                  description: "Generate comprehensive security reports for audit and compliance"
                }
              ].map((feature, index) => (
                <div
                  key={index}
                  className={`p-8 rounded-xl border ${isDarkMode ? 'bg-slate-700/50 border-slate-600 hover:bg-slate-700' : 'bg-white border-slate-200 hover:shadow-lg'} transition-all duration-300 group cursor-pointer`}
                >
                  <div className="mb-4">
                    <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-gradient-to-br from-purple-600 to-purple-700 text-white group-hover:scale-110 transition-transform">
                      <feature.icon size={24} />
                    </div>
                  </div>
                  <h3 className={`text-lg font-bold mb-2 ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>
                    {feature.title}
                  </h3>
                  <p className={`${isDarkMode ? 'text-slate-400' : 'text-slate-600'}`}>
                    {feature.description}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Benefits Section */}
        <section className={`py-20 px-6 ${isDarkMode ? 'bg-slate-900' : 'bg-white'}`}>
          <div className="w-full mx-auto">
            <div className="text-center mb-16">
              <h2 className={`text-4xl md:text-5xl font-bold mb-4 ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>
                Why Choose Us?
              </h2>
            </div>

            <div className="grid md:grid-cols-2 gap-12">
              {[
                {
                  title: "Real-Time Monitoring",
                  description: "Get instant alerts and continuous security monitoring for your domains 24/7"
                },
                {
                  title: "Expert Insights",
                  description: "Actionable recommendations from security experts to fix vulnerabilities"
                },
                {
                  title: "Easy Integration",
                  description: "Simple API and webhook support to integrate with your existing tools"
                },
                {
                  title: "Detailed Reports",
                  description: "Comprehensive PDF reports for compliance, audits, and stakeholder updates"
                },
                {
                  title: "Enterprise Support",
                  description: "Dedicated support team available for enterprise and critical deployments"
                },
                {
                  title: "Affordable Pricing",
                  description: "Flexible plans starting from free tier to enterprise solutions"
                }
              ].map((benefit, index) => (
                <div key={index} className="flex gap-4">
                  <div className="flex-shrink-0">
                    <CheckCircle2 size={28} className="text-green-500" />
                  </div>
                  <div>
                    <h3 className={`text-xl font-bold mb-2 ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>
                      {benefit.title}
                    </h3>
                    <p className={`${isDarkMode ? 'text-slate-400' : 'text-slate-600'}`}>
                      {benefit.description}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className={`py-20 px-6 ${isDarkMode ? 'bg-gradient-to-r from-purple-900 to-purple-900' : 'bg-gradient-to-r from-purple-600 to-purple-700'}`}>
          <div className="w-full mx-auto text-center">
            <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
              Ready to Secure Your Domain?
            </h2>
            <p className="text-xl text-purple-100 mb-8">
              Join thousands of organizations already using our platform to protect their digital infrastructure
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link to="/auth">
                <button className="px-8 py-4 bg-white text-purple-600 font-bold rounded-lg hover:bg-slate-100 transition-colors duration-300 shadow-lg">
                  Get Started Free
                </button>
              </Link>
              <button className="px-8 py-4 border-2 border-white text-white font-bold rounded-lg hover:bg-white/10 transition-colors duration-300">
                Schedule Demo
              </button>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer className={`py-12 px-6 border-t ${isDarkMode ? 'bg-slate-900 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
          <div className="w-full mx-auto">
            <div className="grid md:grid-cols-4 gap-8 mb-8">
              <div>
                <h4 className={`font-bold mb-4 ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>Product</h4>
                <ul className={`space-y-2 ${isDarkMode ? 'text-slate-400' : 'text-slate-600'}`}>
                  <li><a href="#" className="hover:text-purple-600">Features</a></li>
                  <li><a href="#" className="hover:text-purple-600">Pricing</a></li>
                  <li><a href="#" className="hover:text-purple-600">Security</a></li>
                </ul>
              </div>
              <div>
                <h4 className={`font-bold mb-4 ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>Company</h4>
                <ul className={`space-y-2 ${isDarkMode ? 'text-slate-400' : 'text-slate-600'}`}>
                  <li><a href="#" className="hover:text-purple-600">About</a></li>
                  <li><a href="#" className="hover:text-purple-600">Blog</a></li>
                  <li><a href="#" className="hover:text-purple-600">Careers</a></li>
                </ul>
              </div>
              <div>
                <h4 className={`font-bold mb-4 ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>Legal</h4>
                <ul className={`space-y-2 ${isDarkMode ? 'text-slate-400' : 'text-slate-600'}`}>
                  <li><a href="#" className="hover:text-purple-600">Privacy</a></li>
                  <li><a href="#" className="hover:text-purple-600">Terms</a></li>
                  <li><a href="#" className="hover:text-purple-600">Contact</a></li>
                </ul>
              </div>
              <div>
                <h4 className={`font-bold mb-4 ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>Follow</h4>
                <ul className={`space-y-2 ${isDarkMode ? 'text-slate-400' : 'text-slate-600'}`}>
                  <li><a href="#" className="hover:text-purple-600">Twitter</a></li>
                  <li><a href="#" className="hover:text-purple-600">LinkedIn</a></li>
                  <li><a href="#" className="hover:text-purple-600">GitHub</a></li>
                </ul>
              </div>
            </div>
            <div className={`border-t ${isDarkMode ? 'border-slate-800' : 'border-slate-200'} pt-8 text-center ${isDarkMode ? 'text-slate-400' : 'text-slate-600'}`}>
              <p>&copy; 2024. All rights reserved.</p>
            </div>
          </div>
        </footer>
      </main>
    </div>
  );
}

export default LandingPage
