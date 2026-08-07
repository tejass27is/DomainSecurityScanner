import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Eye, EyeOff, Loader2, ArrowLeft, Shield, Globe, Lock, TrendingUp, CheckCircle2 } from "lucide-react";
import { useGoogleReCaptcha } from "react-google-recaptcha-v3";
import { loginUser, registerUser, forgotPassword, resetPassword, resetPasswordWithOtp, setupTotp, verifyTotp, resetTotp } from "../services/api";
import QRCode from "react-qr-code";
// @ts-ignore
import isecurify_logo from "../assets/isecurify_logo.png";

function AuthPage() {
   const navigate = useNavigate();
   const { executeRecaptcha } = useGoogleReCaptcha();

   // "login" | "signup" | "forgot" | "reset-otp"
   const [view, setView] = useState("login");

   // ─── Shared state ──────────────────────────────────────────────────────────
   const [email, setEmail] = useState(() => {
      const params = new URLSearchParams(window.location.search);
      return params.get("email") || "";
   });
   const [password, setPassword] = useState("");
   const [confirmPassword, setConfirmPassword] = useState("");
   const [domain, setDomain] = useState("");
   const [otp, setOtp] = useState("");
   const [totpCode, setTotpCode] = useState("");
   const [totpSetupUri, setTotpSetupUri] = useState("");
   const [totpSecret, setTotpSecret] = useState("");
   const [newPassword, setNewPassword] = useState("");
   const [inviteToken] = useState(() => new URLSearchParams(window.location.search).get("invite_token") || "");
   const hasInviteToken = Boolean(inviteToken);
   const [resetRequested, setResetRequested] = useState(false);

   const [loading, setLoading] = useState(false);
   const [error, setError] = useState("");
   const [success, setSuccess] = useState("");

   const PASSWORD_POLICY_MESSAGE = "Use at least 8 characters, including 1 uppercase letter, 1 number, and 1 special character.";
   const PASSWORD_POLICY_REGEX = /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;

   const validateStrongPassword = (value) => {
      if (value.length < 8) {
         return "Password must be at least 8 characters.";
      }
      if (!/[A-Z]/.test(value)) {
         return "Password must include at least one uppercase letter.";
      }
      if (!/\d/.test(value)) {
         return "Password must include at least one number.";
      }
      if (!/[^A-Za-z0-9]/.test(value)) {
         return "Password must include at least one special character.";
      }
      return "";
   };
   // Separate visibility toggles
   const [loginShowPassword, setLoginShowPassword] = useState(false);
   const [signupShowPassword, setSignupShowPassword] = useState(false);
   const [signupShowConfirmPassword, setSignupShowConfirmPassword] = useState(false);
   const [showNewPassword, setShowNewPassword] = useState(false);

   // ─── Reset form when switching views ───────────────────────────────────────
   const switchView = (newView) => {
      const keepEmail = ["reset-otp", "totp-setup", "totp-verify", "totp-reset"].includes(newView);
      const keepPassword = ["totp-setup", "totp-verify"].includes(newView);
      setView(newView);
      setEmail(keepEmail ? email : "");
      setPassword(keepPassword ? password : "");
      setConfirmPassword("");
      setDomain("");
      setOtp("");
      setNewPassword("");
      setTotpCode("");
      setResetRequested(false);
      if (!["totp-setup", "totp-verify"].includes(newView)) {
         setTotpSetupUri("");
         setTotpSecret("");
      }
      setError("");
      setSuccess("");
   };

   // ─── Login handler ────────────────────────────────────────────────────────
   const handleLogin = async (e) => {
      e.preventDefault();
      setError("");
      setSuccess("");

      if (!email || !password) {
         setError("Please fill all the fields");
         return;
      }

      setLoading(true);
      try {
         const captchaEnabled = import.meta.env.VITE_RECAPTCHA_ENABLED === 'true';
         let captchaToken = undefined;

         if (captchaEnabled) {
            if (!executeRecaptcha) {
               setError("reCAPTCHA not initialized. Please try again later.");
               setLoading(false);
               return;
            }
            captchaToken = await executeRecaptcha("login");
         }

         const data = await loginUser(email, password, captchaToken);

         if (data?.requires_totp_setup) {
            const setup = await setupTotp(email, password);
            setTotpSetupUri(setup.otpauth_uri || "");
            setTotpSecret(setup.secret || "");
            setView("totp-setup");
            return;
         }

         if (data?.requires_totp_verify) {
            setView("totp-verify");
            return;
         }

         if (data?.token) {
            localStorage.setItem("token", data.token);
            localStorage.setItem("user", JSON.stringify(data.user));

            if (data.user?.must_change_password) {
               setView("change-password");
               setSuccess("");
               return;
            }

            if (data.user?.role === "admin" || data.user?.role === "marketing" || data.user?.role === "soc_analyst") {
               navigate("/admin");
            } else {
               navigate("/scan-dashboard");
            }
            return;
         }

         setError(data?.message || "Unable to sign in. Please try again.");
      } catch (err) {
         setError(err.message);
      } finally {
         setLoading(false);
      }
   };


   // ─── First-login forced password change (provisioned accounts) ────────────
   const handleFirstLoginPasswordChange = async (e) => {
      e.preventDefault();
      setError("");
      setSuccess("");

      if (!password || !newPassword || !confirmPassword) {
         setError("Please fill all the fields");
         return;
      }
      const passwordError = validateStrongPassword(newPassword);
      if (passwordError) {
         setError(passwordError);
         return;
      }
      if (newPassword !== confirmPassword) {
         setError("Passwords do not match");
         return;
      }

      setLoading(true);
      try {
         const token = localStorage.getItem("token");
         if (!token) throw new Error("Authentication required.");

         await resetPassword(password, newPassword, token);

         const storedUser = JSON.parse(localStorage.getItem("user") || "null");
         if (storedUser) {
            localStorage.setItem("user", JSON.stringify({ ...storedUser, must_change_password: false }));
         }
         setPassword("");
         setNewPassword("");
         setConfirmPassword("");
         setSuccess("Password updated successfully. Taking you to your dashboard…");

         setTimeout(() => {
            const user = JSON.parse(localStorage.getItem("user") || "null");
            if (user?.role === "admin" || user?.role === "marketing" || user?.role === "soc_analyst") {
               navigate("/admin");
            } else {
               navigate("/scan-dashboard");
            }
         }, 800);
      } catch (err) {
         setError(err.message);
      } finally {
         setLoading(false);
      }
   };

   // ─── Register handler ─────────────────────────────────────────────────────
   const handleRegister = async (e) => {
      e.preventDefault();
      setError("");
      setSuccess("");

      if (!email || !password || !confirmPassword) {
         setError("Please fill all required fields");
         return;
      }

      // For regular signups (no invite): domain is required
      // For invited users: domain is optional
      if (!hasInviteToken && !domain.trim()) {
         setError("Domain is required for new organization signup");
         return;
      }

      if (password !== confirmPassword) {
         setError("Passwords do not match");
         return;
      }

      const passwordError = validateStrongPassword(password);
      if (passwordError) {
         setError(passwordError);
         return;
      }

      setLoading(true);
      try {
         const captchaEnabled = import.meta.env.VITE_RECAPTCHA_ENABLED === 'true';
         let captchaToken = undefined;

         if (captchaEnabled) {
            if (!executeRecaptcha) {
               setError("reCAPTCHA not initialized. Please try again later.");
               setLoading(false);
               return;
            }
            captchaToken = await executeRecaptcha("register");
         }

         const data = await registerUser(email, password, domain.trim(), captchaToken, inviteToken);
         setSuccess(
            data.message ||
            "Check your email for a verification link to complete registration."
         );
         setPassword("");
         setConfirmPassword("");
      } catch (err) {
         setError(err.message);
      } finally {
         setLoading(false);
      }
   };

   // ─── Forgot Password – Step 1: Send OTP ──────────────────────────────────
   const handleConfirmTotpSetup = async (e) => {
      e.preventDefault();
      setError("");
      setSuccess("");

      if (!totpCode) {
         setError("Please enter the 6-digit code from your authenticator app.");
         return;
      }

      setLoading(true);
      try {
         const data = await verifyTotp(email, password, totpCode);

         if (data?.token) {
            localStorage.setItem("token", data.token);
            localStorage.setItem("user", JSON.stringify(data.user));

            if (data.user?.must_change_password) {
               setView("change-password");
               setSuccess("");
               return;
            }

            if (data.user?.role === "admin" || data.user?.role === "marketing" || data.user?.role === "soc_analyst") {
               navigate("/admin");
            } else {
               navigate("/scan-dashboard");
            }
            return;
         }

         setError(data?.message || "TOTP verification failed. Please try again.");
      } catch (err) {
         setError(err.message);
      } finally {
         setLoading(false);
      }
   };

   const handleVerifyTotp = async (e) => {
      e.preventDefault();
      setError("");
      setSuccess("");

      if (!totpCode) {
         setError("Please enter the 6-digit code from your authenticator app.");
         return;
      }

      setLoading(true);
      try {
         const data = await verifyTotp(email, password, totpCode);

         if (data?.token) {
            localStorage.setItem("token", data.token);
            localStorage.setItem("user", JSON.stringify(data.user));

            if (data.user?.must_change_password) {
               setView("change-password");
               setSuccess("");
               return;
            }

            if (data.user?.role === "admin" || data.user?.role === "marketing" || data.user?.role === "soc_analyst") {
               navigate("/admin");
            } else {
               navigate("/scan-dashboard");
            }
            return;
         }

         setError(data?.message || "TOTP verification failed. Please try again.");
      } catch (err) {
         setError(err.message);
      } finally {
         setLoading(false);
      }
   };

   const handleSendTotpResetOtp = async (e) => {
      e?.preventDefault();
      setError("");
      setSuccess("");

      if (!email) {
         setError("Please enter your email address to receive a reset OTP.");
         return;
      }

      setLoading(true);
      try {
         const data = await forgotPassword(email);
         setSuccess(data.message || "OTP sent to your email. Enter it below to reset authenticator.");
         setResetRequested(true);
      } catch (err) {
         setError(err.message);
      } finally {
         setLoading(false);
      }
   };

   const handleResetTotp = async (e) => {
      e.preventDefault();
      setError("");
      setSuccess("");

      if (!email || !otp) {
         setError("Please enter your email and OTP to reset the authenticator.");
         return;
      }

      setLoading(true);
      try {
         const data = await resetTotp(email, otp);
         setSuccess(data.message || "Your authenticator is reset. Please login again.");
         setTimeout(() => {
            switchView("login");
         }, 1500);
      } catch (err) {
         setError(err.message);
      } finally {
         setLoading(false);
      }
   };

   const handleForgotPassword = async (e) => {
      e.preventDefault();
      setError("");
      setSuccess("");

      if (!email) {
         setError("Please enter your email address");
         return;
      }

      setLoading(true);
      try {
         const data = await forgotPassword(email);
         setSuccess(data.message || "OTP sent to your email!");
         // Move to OTP verification step (keep the email)
         setTimeout(() => {
            setView("reset-otp");
            setSuccess("");
         }, 1000);
      } catch (err) {
         setError(err.message);
      } finally {
         setLoading(false);
      }
   };

   // ─── Forgot Password – Step 2: Verify OTP & Reset ────────────────────────
   const handleResetWithOtp = async (e) => {
      e.preventDefault();
      setError("");
      setSuccess("");

      if (!otp || !newPassword) {
         setError("Please fill all the fields");
         return;
      }
      const passwordError = validateStrongPassword(newPassword);
      if (passwordError) {
         setError(passwordError);
         return;
      }

      setLoading(true);
      try {
         const data = await resetPasswordWithOtp(email, otp, newPassword);

         if (data.token && data.user) {
            localStorage.setItem("token", data.token);
            localStorage.setItem("user", JSON.stringify(data.user));

            if (data.user?.must_change_password) {
               setView("change-password");
               setSuccess("");
               return;
            }

            if (data.user?.role === "admin" || data.user?.role === "marketing" || data.user?.role === "soc_analyst") {
               navigate("/admin");
            } else {
               navigate("/scan-dashboard");
            }
            return;
         }

         if (data.message) {
            setSuccess(data.message);
         }

         setTimeout(() => {
            switchView("login");
         }, 1500);
      } catch (err) {
         setError(err.message);
      } finally {
         setLoading(false);
      }
   };

   // ─── Titles & subtitles per view ──────────────────────────────────────────
   const titles = {
      login: { heading: "Welcome Back", sub: "Authenticate to access your dashboard" },
      signup: {
         heading: hasInviteToken ? "Finish Your Invitation" : "Create Account",
         sub: hasInviteToken
            ? "Create your password. Domain is optional for invited users."
            : "Join the ecosystem of digital trust",
      },
      forgot: { heading: "Forgot Password", sub: "Enter your email to receive a reset OTP" },
      "reset-otp": { heading: "Reset Password", sub: "Enter the OTP sent to your email" },
      "totp-setup": { heading: "Set Up Authenticator", sub: "Scan the QR code and enter a code from your app." },
      "totp-verify": { heading: "Verify Authenticator", sub: "Enter the code from your authenticator app to sign in." },
      "totp-reset": { heading: "Lost Authenticator App", sub: "Reset your authenticator with an email OTP." },
      "change-password": { heading: "Set a New Password", sub: "You're using a temporary password — create your own before continuing." },
   };

   const { heading, sub } = titles[view];

   useEffect(() => {
      if (hasInviteToken && view === "login") {
         setView("signup");
      }
   }, [hasInviteToken, view]);

   return (
      <div className="min-h-screen flex flex-col bg-gradient-to-br from-slate-50 to-purple-50 dark:from-slate-900 dark:to-slate-800 font-body relative overflow-hidden">
         <main className="flex-grow flex min-h-screen items-center justify-center px-4 py-12 relative z-10">

            <div className="w-full grid lg:grid-cols-2 gap-8 max-w-6xl items-center">
               {/* Left side - Feature showcase (hidden on small screens) */}
               <div className="hidden lg:flex flex-col justify-center">
                  <div className="mb-8">
                     <h2 className="text-4xl font-bold text-slate-900 dark:text-white mb-4">
                        Enterprise Security at Your Fingertips
                     </h2>
                     <p className="text-lg text-slate-600 dark:text-slate-300">
                        Comprehensive domain security analysis powered by real-time threat intelligence
                     </p>
                  </div>

                  <div className="space-y-4">
                     <div className="flex gap-4 items-start">
                        <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center">
                           <Shield size={20} className="text-purple-600 dark:text-purple-400" />
                        </div>
                        <div>
                           <h3 className="font-bold text-slate-900 dark:text-white">SSL Certificate Verification</h3>
                           <p className="text-sm text-slate-600 dark:text-slate-400">Detect expired certs and protocol vulnerabilities</p>
                        </div>
                     </div>

                     <div className="flex gap-4 items-start">
                        <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center">
                           <Globe size={20} className="text-purple-600 dark:text-purple-400" />
                        </div>
                        <div>
                           <h3 className="font-bold text-slate-900 dark:text-white">DNS & DNSSEC Analysis</h3>
                           <p className="text-sm text-slate-600 dark:text-slate-400">Monitor DNS integrity and prevent tampering</p>
                        </div>
                     </div>

                     <div className="flex gap-4 items-start">
                        <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
                           <Lock size={20} className="text-green-600 dark:text-green-400" />
                        </div>
                        <div>
                           <h3 className="font-bold text-slate-900 dark:text-white">Malware & Threat Detection</h3>
                           <p className="text-sm text-slate-600 dark:text-slate-400">Real-time scanning against global threat databases</p>
                        </div>
                     </div>

                     <div className="flex gap-4 items-start">
                        <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center">
                           <TrendingUp size={20} className="text-purple-600 dark:text-purple-400" />
                        </div>
                        <div>
                           <h3 className="font-bold text-slate-900 dark:text-white">Port Security Scanning</h3>
                           <p className="text-sm text-slate-600 dark:text-slate-400">Identify open ports and vulnerable services</p>
                        </div>
                     </div>
                  </div>

                  {/* Trust Badges */}
                  <div className="mt-8 pt-8 border-t border-slate-200 dark:border-slate-700">
                     <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">Trusted by enterprises worldwide</p>
                     <div className="flex gap-4">
                        <div className="text-sm">
                           <div className="font-bold text-slate-900 dark:text-white">50K+</div>
                           <div className="text-slate-600 dark:text-slate-400">Domains Scanned</div>
                        </div>
                        <div className="text-sm">
                           <div className="font-bold text-slate-900 dark:text-white">99.9%</div>
                           <div className="text-slate-600 dark:text-slate-400">Uptime SLA</div>
                        </div>
                        <div className="text-sm">
                           <div className="font-bold text-slate-900 dark:text-white">ISO 27001</div>
                           <div className="text-slate-600 dark:text-slate-400">Certified</div>
                        </div>
                     </div>
                  </div>
               </div>

               {/* Right side - Auth Form */}
               <div className="w-full max-w-lg z-10">

                  {/* Brand */}
                  <div className="text-center mb-8 max-[480px]:mb-6">
                     <div className="mb-4 flex justify-center">
                        <div className="bg-white dark:bg-slate-700 p-3 rounded-2xl shadow-lg">
                           <img
                              src={isecurify_logo}
                              alt="Logo"
                              className="rounded-lg h-10 w-auto object-contain dark:brightness-200"
                           />
                        </div>
                     </div>

                     <h1 className="text-4xl max-[480px]:text-3xl font-extrabold font-headline text-slate-900 dark:text-white">
                        Domain Security Intelligence
                     </h1>
                  </div>

               {/* Card */}
               <div className="bg-white dark:bg-slate-800 py-8 px-6 sm:py-8 sm:px-8 rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700">

                  {/* Back arrow for forgot / reset views */}
                  {(view === "forgot" || view === "reset-otp" || view === "totp-reset" || view === "totp-setup" || view === "totp-verify") && (
                     <button
                        onClick={() => switchView("login")}
                        className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-400 hover:text-purple-600 dark:hover:text-purple-400 mb-6 transition font-semibold"
                     >
                        <ArrowLeft size={18} /> Back
                     </button>
                  )}

                  {/* TITLE */}
                  <div className="text-center mx-auto max-w-xl">
                     <h2 className="text-3xl max-[480px]:text-2xl font-bold mb-2 text-slate-900 dark:text-white">{heading}</h2>
                     <p className="text-slate-600 dark:text-slate-400 mb-6 text-sm leading-relaxed">{sub}</p>
                     {hasInviteToken && (
                        <div className="mb-6 rounded-lg border border-emerald-200 dark:border-emerald-900/50 bg-emerald-50 dark:bg-emerald-900/20 px-4 py-3 text-sm text-emerald-700 dark:text-emerald-300 font-medium">
                           <span className="font-bold">✓ Invitation Detected</span> — Complete your registration to get started
                        </div>
                     )}
                  </div>

                  {/* ─── Error / Success banners ─── */}
                  {error && (
                     <div className="mb-6 p-4 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 text-sm font-medium flex items-start gap-3">
                        <span className="text-lg">⚠️</span>
                        <span>{error}</span>
                     </div>
                  )}
                  {success && (
                     <div className="mb-6 p-4 rounded-lg bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 text-green-700 dark:text-green-300 text-sm font-medium flex items-start gap-3">
                        <span className="text-lg">✓</span>
                        <span>{success}</span>
                     </div>
                  )}

                  {/* ================= LOGIN ================= */}
                  {view === "login" && (
                     <form className="mx-auto max-w-lg space-y-6 max-[480px]:space-y-4" onSubmit={handleLogin}>
                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              Email Address
                           </label>
                           <input
                              id="login-email"
                              type="email"
                              placeholder="your@email.com"
                              value={email}
                              onChange={(e) => setEmail(e.target.value)}
                              className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white dark:placeholder-slate-500 transition placeholder:text-slate-400"
                           />
                        </div>

                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              Password
                           </label>
                           <div className="relative">
                              <input
                                 id="login-password"
                                 type={loginShowPassword ? "text" : "password"}
                                 placeholder="••••••••"
                                 value={password}
                                 onChange={(e) => setPassword(e.target.value)}
                                 className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white transition"
                              />
                              <button
                                 type="button"
                                 onClick={() => setLoginShowPassword(!loginShowPassword)}
                                 className="absolute right-4 top-3 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300"
                              >
                                 {loginShowPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                              </button>
                           </div>
                        </div>

                        <div className="flex flex-col gap-2 text-right">
                           <button
                              type="button"
                              onClick={() => switchView("forgot")}
                              className="text-sm text-purple-600 dark:text-purple-400 font-semibold hover:underline transition"
                           >
                              Forgot Password?
                           </button>
                           <button
                              type="button"
                              onClick={() => switchView("totp-reset")}
                              className="text-xs text-slate-600 dark:text-slate-400 hover:text-purple-600 dark:hover:text-purple-400 hover:underline transition"
                           >
                              Lost authenticator app?
                           </button>
                        </div>

                        <button
                           id="login-submit"
                           type="submit"
                           disabled={loading}
                           className="w-full py-3 bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white rounded-lg font-bold transition disabled:opacity-60 flex items-center justify-center gap-2 shadow-lg hover:shadow-xl"
                        >
                           {loading && <Loader2 size={20} className="animate-spin" />}
                           {loading ? "Signing In…" : "Sign In"}
                        </button>

                        <p className="text-xs text-slate-600 dark:text-slate-400 text-center">
                           This site is protected by reCAPTCHA and the Google{" "}
                           <a href="https://policies.google.com/privacy" className="text-purple-600 dark:text-purple-400 hover:underline">Privacy Policy</a> and{" "}
                           <a href="https://policies.google.com/terms" className="text-purple-600 dark:text-purple-400 hover:underline">Terms of Service</a> apply.
                        </p>
                     </form>
                  )}

                  {/* ================= FIRST-LOGIN PASSWORD CHANGE ================= */}
                  {view === "change-password" && (
                     <form className="mx-auto max-w-lg space-y-6 max-[480px]:space-y-4" onSubmit={handleFirstLoginPasswordChange}>
                        <div className="rounded-lg border border-amber-200 dark:border-amber-900/50 bg-amber-50 dark:bg-amber-900/20 px-4 py-3 text-sm text-amber-700 dark:text-amber-300 font-medium">
                           Your administrator issued a temporary password. Set your own password to continue.
                        </div>

                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              Current (Temporary) Password
                           </label>
                           <input
                              id="change-password-current"
                              type="password"
                              placeholder="Temporary password from the email"
                              value={password}
                              onChange={(e) => setPassword(e.target.value)}
                              className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white transition"
                           />
                        </div>

                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              New Password
                           </label>
                           <input
                              id="change-password-new"
                              type="password"
                              placeholder="At least 8 chars, 1 uppercase, 1 number, 1 special"
                              value={newPassword}
                              onChange={(e) => setNewPassword(e.target.value)}
                              className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white transition"
                           />
                           <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{PASSWORD_POLICY_MESSAGE}</p>
                        </div>

                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              Confirm New Password
                           </label>
                           <input
                              id="change-password-confirm"
                              type="password"
                              placeholder="Re-enter the new password"
                              value={confirmPassword}
                              onChange={(e) => setConfirmPassword(e.target.value)}
                              className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white transition"
                           />
                        </div>

                        <button
                           id="change-password-submit"
                           type="submit"
                           disabled={loading}
                           className="w-full py-3 bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white rounded-lg font-bold transition disabled:opacity-60 flex items-center justify-center gap-2 shadow-lg hover:shadow-xl"
                        >
                           {loading && <Loader2 size={20} className="animate-spin" />}
                           {loading ? "Updating…" : "Update Password & Continue"}
                        </button>
                     </form>
                  )}

                  {/* ================= TOTP SETUP ================= */}
                  {view === "totp-setup" && (
                     <form className="mx-auto max-w-lg space-y-6 max-[480px]:space-y-4" onSubmit={handleConfirmTotpSetup}>
                        <p className="text-sm text-slate-600 dark:text-slate-400">
                           Scan the QR code below with Google Authenticator or Microsoft Authenticator, then enter the 6-digit code.
                        </p>

                        {totpSetupUri ? (
                           <div className="flex justify-center py-6 bg-slate-50 dark:bg-slate-700/50 rounded-lg">
                              <div className="inline-flex rounded-2xl border border-slate-200 dark:border-slate-600 p-4 bg-white dark:bg-slate-800">
                                 <QRCode
                                    value={totpSetupUri}
                                    size={180}
                                    level="H"
                                    includeMargin={true}
                                    renderAs="svg"
                                    bgColor="#FFFFFF"
                                    fgColor="#0F172A"
                                    style={{
                                       display: "block",
                                       width: 180,
                                       height: 180
                                    }}
                                 />
                              </div>
                           </div>
                        ) : (
                           <div className="text-sm text-slate-600 dark:text-slate-400 text-center py-6">Preparing authenticator setup...</div>
                        )}

                        {totpSecret && (
                           <div className="rounded-lg border border-slate-300 dark:border-slate-600 bg-slate-50 dark:bg-slate-700/50 p-4">
                              <div className="text-xs font-bold text-slate-700 dark:text-slate-300 mb-2 uppercase">Can't scan? Enter this key manually:</div>
                              <div className="font-mono text-sm text-slate-900 dark:text-slate-100 break-all font-bold tracking-wider">{totpSecret}</div>
                           </div>
                        )}

                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              6-Digit Code
                           </label>
                           <input
                              id="totp-setup-code"
                              type="text"
                              inputMode="numeric"
                              placeholder="000000"
                              maxLength={6}
                              value={totpCode}
                              onChange={(e) => setTotpCode(e.target.value.replace(/[^0-9]/g, ""))}
                              className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white transition tracking-widest text-center text-lg font-mono"
                           />
                        </div>

                        <button
                           id="totp-setup-submit"
                           type="submit"
                           disabled={loading}
                           className="w-full py-3 bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white rounded-lg font-bold transition disabled:opacity-60 flex items-center justify-center gap-2 shadow-lg hover:shadow-xl"
                        >
                           {loading && <Loader2 size={20} className="animate-spin" />}
                           {loading ? "Verifying…" : "Verify & Complete Setup"}
                        </button>
                     </form>
                  )}

                  {/* ================= TOTP VERIFY ================= */}
                  {view === "totp-verify" && (
                     <form className="mx-auto max-w-lg space-y-6 max-[480px]:space-y-4" onSubmit={handleVerifyTotp}>
                        <p className="text-sm text-slate-600 dark:text-slate-400">
                           Enter the 6-digit code from your authenticator app to complete sign in.
                        </p>

                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              6-Digit Code
                           </label>
                           <input
                              id="totp-verify-code"
                              type="text"
                              inputMode="numeric"
                              placeholder="000000"
                              maxLength={6}
                              value={totpCode}
                              onChange={(e) => setTotpCode(e.target.value.replace(/[^0-9]/g, ""))}
                              className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white transition tracking-widest text-center text-lg font-mono"
                           />
                        </div>

                        <button
                           id="totp-verify-submit"
                           type="submit"
                           disabled={loading}
                           className="w-full py-3 bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white rounded-lg font-bold transition disabled:opacity-60 flex items-center justify-center gap-2 shadow-lg hover:shadow-xl"
                        >
                           {loading && <Loader2 size={20} className="animate-spin" />}
                           {loading ? "Verifying…" : "Verify & Sign In"}
                        </button>
                     </form>
                  )}

                  {/* ================= TOTP RESET ================= */}
                  {view === "totp-reset" && (
                     <form className="mx-auto max-w-lg space-y-6 max-[480px]:space-y-4" onSubmit={resetRequested ? handleResetTotp : handleSendTotpResetOtp}>
                        <p className="text-sm text-slate-600 dark:text-slate-400">
                           {resetRequested
                              ? "Enter the one-time password sent to your email to reset your authenticator app."
                              : "Verify your email to receive a one-time password and reset your authenticator app."}
                        </p>

                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              Email Address
                           </label>
                           <input
                              id="totp-reset-email"
                              type="email"
                              placeholder="your@email.com"
                              value={email}
                              onChange={(e) => setEmail(e.target.value)}
                              className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white dark:placeholder-slate-500 transition placeholder:text-slate-400"
                           />
                        </div>

                        {resetRequested && (
                           <div>
                              <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                                 OTP Code
                              </label>
                              <input
                                 id="totp-reset-otp"
                                 type="text"
                                 placeholder="000000"
                                 maxLength={6}
                                 value={otp}
                                 onChange={(e) => setOtp(e.target.value.replace(/[^0-9]/g, ""))}
                                 className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white transition tracking-widest text-center text-lg font-mono"
                              />
                           </div>
                        )}

                        <button
                           id="totp-reset-submit"
                           type="submit"
                           disabled={loading}
                           className="w-full py-3 bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white rounded-lg font-bold transition disabled:opacity-60 flex items-center justify-center gap-2 shadow-lg hover:shadow-xl"
                        >
                           {loading && <Loader2 size={20} className="animate-spin" />}
                           {loading ? "Processing…" : resetRequested ? "Submit & Reset Authenticator" : "Send Reset OTP"}
                        </button>
                     </form>
                  )}

                  {/* ================= SIGNUP ================= */}
                  {view === "signup" && (
                     <form className="mx-auto max-w-lg space-y-6 max-[480px]:space-y-4" onSubmit={handleRegister}>
                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              Email Address
                           </label>
                           <input
                              id="register-email"
                              type="email"
                              placeholder="your@email.com"
                              value={email}
                              onChange={(e) => setEmail(e.target.value)}
                              className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white dark:placeholder-slate-500 transition placeholder:text-slate-400"
                           />
                        </div>

                        <div className="space-y-3">
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300">
                              Password & Confirmation
                           </label>
                           <div className="grid sm:grid-cols-2 gap-3">
                              <div className="relative">
                                 <input
                                    id="register-password"
                                    type={signupShowPassword ? "text" : "password"}
                                    placeholder="Password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white transition"
                                 />
                                 <button
                                    type="button"
                                    onClick={() => setSignupShowPassword(!signupShowPassword)}
                                    className="absolute right-4 top-3 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300"
                                 >
                                    {signupShowPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                                 </button>
                              </div>

                              <div className="relative">
                                 <input
                                    id="register-confirm-password"
                                    type={signupShowConfirmPassword ? "text" : "password"}
                                    placeholder="Confirm"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white transition"
                                 />
                                 <button
                                    type="button"
                                    onClick={() => setSignupShowConfirmPassword(!signupShowConfirmPassword)}
                                    className="absolute right-4 top-3 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300"
                                 >
                                    {signupShowConfirmPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                                 </button>
                              </div>
                           </div>
                           <p className="text-xs text-slate-600 dark:text-slate-400 flex items-start gap-2">
                              <span className="text-lg leading-none">ℹ️</span>
                              <span>{PASSWORD_POLICY_MESSAGE}</span>
                           </p>
                        </div>

                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              Domain {hasInviteToken ? "(Optional)" : "(Required)"}
                           </label>
                           <input
                              id="register-domain"
                              type="text"
                              placeholder={hasInviteToken ? "example.com (optional)" : "example.com"}
                              value={domain}
                              onChange={(e) => setDomain(e.target.value)}
                              className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white dark:placeholder-slate-500 transition placeholder:text-slate-400"
                           />
                        </div>

                        <button
                           id="register-submit"
                           type="submit"
                           disabled={loading}
                           className="w-full py-3 bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white rounded-lg font-bold transition disabled:opacity-60 flex items-center justify-center gap-2 shadow-lg hover:shadow-xl"
                        >
                           {loading && <Loader2 size={20} className="animate-spin" />}
                           {loading ? "Creating Account…" : "Create Account"}
                        </button>

                        <p className="text-xs text-slate-600 dark:text-slate-400 text-center">
                           This site is protected by reCAPTCHA and the Google{" "}
                           <a href="https://policies.google.com/privacy" className="text-purple-600 dark:text-purple-400 hover:underline">Privacy Policy</a> and{" "}
                           <a href="https://policies.google.com/terms" className="text-purple-600 dark:text-purple-400 hover:underline">Terms of Service</a> apply.
                        </p>

                        {/* Benefits for signup */}
                        <div className="pt-6 border-t border-slate-200 dark:border-slate-700">
                           <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 mb-4 uppercase">What you get:</p>
                           <div className="space-y-2">
                              <div className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                                 <CheckCircle2 size={16} className="text-green-500 flex-shrink-0" />
                                 <span>Instant domain security analysis</span>
                              </div>
                              <div className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                                 <CheckCircle2 size={16} className="text-green-500 flex-shrink-0" />
                                 <span>Real-time threat monitoring</span>
                              </div>
                              <div className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                                 <CheckCircle2 size={16} className="text-green-500 flex-shrink-0" />
                                 <span>Actionable security reports</span>
                              </div>
                           </div>
                        </div>
                     </form>
                  )}

                  {/* ================= FORGOT PASSWORD – Email ================= */}
                  {view === "forgot" && (
                     <form className="mx-auto max-w-lg space-y-6 max-[480px]:space-y-4" onSubmit={handleForgotPassword}>
                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              Email Address
                           </label>
                           <input
                              id="forgot-email"
                              type="email"
                              placeholder="your@email.com"
                              value={email}
                              onChange={(e) => setEmail(e.target.value)}
                              className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white dark:placeholder-slate-500 transition placeholder:text-slate-400"
                           />
                        </div>

                        <button
                           id="forgot-submit"
                           type="submit"
                           disabled={loading}
                           className="w-full py-3 bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white rounded-lg font-bold transition disabled:opacity-60 flex items-center justify-center gap-2 shadow-lg hover:shadow-xl"
                        >
                           {loading && <Loader2 size={20} className="animate-spin" />}
                           {loading ? "Sending OTP…" : "Send Reset OTP"}
                        </button>

                        <p className="text-sm text-slate-600 dark:text-slate-400 text-center">
                           We'll send a one-time password to your email address.
                        </p>
                     </form>
                  )}

                  {/* ================= RESET PASSWORD – OTP + New Password ================= */}
                  {view === "reset-otp" && (
                     <form className="mx-auto max-w-lg space-y-6 max-[480px]:space-y-4" onSubmit={handleResetWithOtp}>
                        <div className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4">
                           <p className="text-sm text-purple-900 dark:text-purple-300">
                              One-time password sent to <span className="font-bold">{email}</span>
                           </p>
                        </div>

                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              OTP Code
                           </label>
                           <input
                              id="reset-otp"
                              type="text"
                              placeholder="000000"
                              maxLength={6}
                              value={otp}
                              onChange={(e) => setOtp(e.target.value)}
                              className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white transition tracking-widest text-center text-lg font-mono"
                           />
                        </div>

                        <div>
                           <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              New Password
                           </label>
                           <div className="relative">
                              <input
                                 id="reset-new-password"
                                 type={showNewPassword ? "text" : "password"}
                                 placeholder="••••••••"
                                 value={newPassword}
                                 onChange={(e) => setNewPassword(e.target.value)}
                                 className="w-full px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:text-white transition"
                              />
                              <button
                                 type="button"
                                 onClick={() => setShowNewPassword(!showNewPassword)}
                                 className="absolute right-4 top-3 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300"
                              >
                                 {showNewPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                              </button>
                           </div>
                           <p className="text-xs text-slate-600 dark:text-slate-400 mt-2">{PASSWORD_POLICY_MESSAGE}</p>
                        </div>

                        <button
                           id="reset-submit"
                           type="submit"
                           disabled={loading}
                           className="w-full py-3 bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white rounded-lg font-bold transition disabled:opacity-60 flex items-center justify-center gap-2 shadow-lg hover:shadow-xl"
                        >
                           {loading && <Loader2 size={20} className="animate-spin" />}
                           {loading ? "Resetting…" : "Reset Password"}
                        </button>
                     </form>
                  )}
                  {(view === "login" || view === "signup") && (
                     <div className="mt-8 pt-8 border-t border-slate-200 dark:border-slate-700 text-center text-sm text-slate-600 dark:text-slate-400">
                        {view === "login" ? "Don't have an account?" : "Already have an account?"}
                        <button
                           onClick={() => switchView(view === "login" ? "signup" : "login")}
                           className="ml-2 text-purple-600 dark:text-purple-400 font-bold hover:underline transition"
                        >
                           {view === "login" ? "Sign Up" : "Sign In"}
                        </button>
                     </div>
                  )}
               </div>
            </div>
            </div>
         </main>
      </div>
   );
}

export default AuthPage;
