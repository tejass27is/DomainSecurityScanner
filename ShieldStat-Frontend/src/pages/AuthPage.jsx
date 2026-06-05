import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Eye, EyeOff, Loader2, ArrowLeft } from "lucide-react";
import { useGoogleReCaptcha } from "react-google-recaptcha-v3";
import { loginUser, registerUser, forgotPassword, resetPasswordWithOtp } from "../services/api";
// @ts-ignore
import isecurify_logo from "../assets/isecurify_logo.png";

function AuthPage() {
   const navigate = useNavigate();
   const { executeRecaptcha } = useGoogleReCaptcha();

   // "login" | "signup" | "forgot" | "reset-otp"
   const [view, setView] = useState("login");

   // ─── Shared state ──────────────────────────────────────────────────────────
   const [email, setEmail] = useState("");
   const [password, setPassword] = useState("");
   const [confirmPassword, setConfirmPassword] = useState("");
   const [domain, setDomain] = useState("");
   const [otp, setOtp] = useState("");
   const [newPassword, setNewPassword] = useState("");

   const [loading, setLoading] = useState(false);
   const [error, setError] = useState("");
   const [success, setSuccess] = useState("");

   // Separate visibility toggles
   const [loginShowPassword, setLoginShowPassword] = useState(false);
   const [signupShowPassword, setSignupShowPassword] = useState(false);
   const [signupShowConfirmPassword, setSignupShowConfirmPassword] = useState(false);
   const [showNewPassword, setShowNewPassword] = useState(false);

   // ─── Reset form when switching views ───────────────────────────────────────
   const switchView = (newView) => {
      setView(newView);
      setEmail(newView === "reset-otp" ? email : ""); // keep email when going to OTP step
      setPassword("");
      setConfirmPassword("");
      setDomain("");
      setOtp("");
      setNewPassword("");
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
         localStorage.setItem("token", data.token);
         localStorage.setItem("user", JSON.stringify(data.user));

         if (data.user?.role === "admin") {
            navigate("/admin");
         } else {
            navigate("/scan-dashboard");
         }
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

      if (!email || !password || !confirmPassword || !domain.trim()) {
         setError("Please fill all the fields");
         return;
      }
      if (password !== confirmPassword) {
         setError("Passwords do not match");
         return;
      }
      if (password.length < 6) {
         setError("Password must be at least 6 characters");
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

         const data = await registerUser(email, password, domain.trim(), captchaToken);
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
      if (newPassword.length < 6) {
         setError("Password must be at least 6 characters");
         return;
      }

      setLoading(true);
      try {
         const data = await resetPasswordWithOtp(email, otp, newPassword);
         setSuccess(data.message || "Password reset successful!");
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
      signup: { heading: "Create Account", sub: "Join the ecosystem of digital trust" },
      forgot: { heading: "Forgot Password", sub: "Enter your email to receive a reset OTP" },
      "reset-otp": { heading: "Reset Password", sub: "Enter the OTP sent to your email" },
   };

   const { heading, sub } = titles[view];

   return (
      <div className="min-h-screen flex flex-col bg-background-light font-body">

         <main className="flex-grow flex min-h-screen items-center justify-center px-4 py-2 relative">

            <div className="w-full max-w-lg lg:max-w-xl z-10">

               {/* Brand */}
               <div className="text-center mb-6 max-[480px]:mb-4">
                  <div className="mb-3 flex justify-center">
                     <div className="bg-white p-2.5 rounded-xl shadow dark:bg-slate-800">
                        <img
                           src={isecurify_logo}
                           alt="isecurify"
                           className="rounded-xl h-8 w-auto object-contain dark:invert dark:brightness-200"
                        />
                     </div>
                  </div>

                  <h1 className="text-3xl max-[480px]:text-2xl font-extrabold font-headline text-on-surface">
                     Domain Security Scanner
                  </h1>

                  <p className="text-[10px] uppercase tracking-[0.4em] mt-3 text-on-surface-variant">
                     Secure Identity Access
                  </p>
               </div>

               {/* Card */}
               <div className="bg-white py-4 px-4 sm:py-5 sm:px-5 md:p-7 rounded-xl shadow border border-slate-200">

                  {/* Back arrow for forgot / reset views */}
                  {(view === "forgot" || view === "reset-otp") && (
                     <button
                        onClick={() => switchView("login")}
                        className="flex items-center gap-1 text-sm text-on-surface-variant hover:text-primary mb-4 transition"
                     >
                        <ArrowLeft size={16} /> Back to Login
                     </button>
                  )}

                  {/* TITLE */}
                  <div className="text-center mx-auto max-w-xl">
                     <h2 className="text-2xl max-[480px]:text-xl font-bold mb-2 text-on-surface">{heading}</h2>
                     <p className="text-on-surface-variant mb-4 text-sm max-[480px]:text-xs">{sub}</p>
                  </div>

                  {/* ─── Error / Success banners ─── */}
                  {error && (
                     <div className="mb-4 p-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
                        {error}
                     </div>
                  )}
                  {success && (
                     <div className="mb-4 p-3 rounded-lg bg-green-50 border border-green-200 text-green-700 text-sm">
                        {success}
                     </div>
                  )}

                  {/* ================= LOGIN ================= */}
                  {view === "login" && (
                     <form className="mx-auto max-w-lg space-y-5 max-[480px]:space-y-3" onSubmit={handleLogin}>
                        <input
                           id="login-email"
                           type="email"
                           placeholder="email@example.com"
                           value={email}
                           onChange={(e) => setEmail(e.target.value)}
                           className="w-full p-2.5 rounded-lg bg-surface-container-low outline-none focus:ring-2 focus:ring-primary/40 placeholder:text-on-surface-variant/70"
                        />

                        <div className="relative">
                           <input
                              id="login-password"
                              type={loginShowPassword ? "text" : "password"}
                              placeholder="••••••••"
                              value={password}
                              onChange={(e) => setPassword(e.target.value)}
                              className="w-full p-2.5 pr-10 rounded-lg bg-surface-container-low outline-none focus:ring-2 focus:ring-primary/40"
                           />
                           <button
                              type="button"
                              onClick={() => setLoginShowPassword(!loginShowPassword)}
                              className="absolute right-3 top-3 text-gray-500 hover:text-gray-700"
                           >
                              {loginShowPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                           </button>
                        </div>

                        {/* Forgot password link */}
                        <div className="text-right -mt-2">
                           <button
                              type="button"
                              onClick={() => switchView("forgot")}
                              className="text-xs text-primary font-semibold hover:underline"
                           >
                              Forgot Password?
                           </button>
                        </div>

                        <button
                           id="login-submit"
                           type="submit"
                           disabled={loading}
                           className="w-full py-2.5 bg-primary text-white rounded-lg font-bold hover:bg-primary-dim transition disabled:opacity-60 flex items-center justify-center gap-2"
                        >
                           {loading && <Loader2 size={18} className="animate-spin" />}
                           {loading ? "Signing In…" : "Sign In"}
                        </button>
                        <p style={{ fontSize: "11px", color: "#888" }}>
                           This site is protected by reCAPTCHA and the Google{" "}
                           <a href="https://policies.google.com/privacy">Privacy Policy</a> and{" "}
                           <a href="https://policies.google.com/terms">Terms of Service</a> apply.
                        </p>
                     </form>
                  )}

                  {/* ================= SIGNUP ================= */}
                  {view === "signup" && (
                     <form className="mx-auto max-w-lg space-y-5 max-[480px]:space-y-3" onSubmit={handleRegister}>
                        <div>
                           <label className="text-[11px] font-semibold text-on-surface-variant">
                              Email Address
                           </label>
                           <input
                              id="register-email"
                              type="email"
                              placeholder="name@example.com"
                              value={email}
                              onChange={(e) => setEmail(e.target.value)}
                              className="w-full mt-1 p-2.5 rounded-lg bg-surface-container-low outline-none focus:ring-2 focus:ring-primary/40 placeholder:text-on-surface-variant/70"
                           />
                        </div>



                        <div className="grid sm:grid-cols-2 gap-2">
                           <div className="relative">
                              <input
                                 id="register-password"
                                 type={signupShowPassword ? "text" : "password"}
                                 placeholder="Password"
                                 value={password}
                                 onChange={(e) => setPassword(e.target.value)}
                                 className="w-full p-2.5 pr-10 rounded-lg bg-surface-container-low outline-none focus:ring-2 focus:ring-primary/40"
                              />
                              <button
                                 type="button"
                                 onClick={() => setSignupShowPassword(!signupShowPassword)}
                                 className="absolute right-3 top-3 text-gray-500 hover:text-gray-700"
                              >
                                 {signupShowPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                              </button>
                           </div>

                           <div className="relative">
                              <input
                                 id="register-confirm-password"
                                 type={signupShowConfirmPassword ? "text" : "password"}
                                 placeholder="Confirm Password"
                                 value={confirmPassword}
                                 onChange={(e) => setConfirmPassword(e.target.value)}
                                 className="w-full p-2.5 pr-10 rounded-lg bg-surface-container-low outline-none focus:ring-2 focus:ring-primary/40"
                              />
                              <button
                                 type="button"
                                 onClick={() => setSignupShowConfirmPassword(!signupShowConfirmPassword)}
                                 className="absolute right-3 top-3 text-gray-500 hover:text-gray-700"
                              >
                                 {signupShowConfirmPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                              </button>
                           </div>
                        </div>

                        <div>
                           <label className="text-[11px] font-semibold text-on-surface-variant">
                              Domain
                           </label>
                           <input
                              id="register-domain"
                              type="text"
                              placeholder="example.com"
                              value={domain}
                              onChange={(e) => setDomain(e.target.value)}
                              className="w-full mt-1 p-2.5 rounded-lg bg-surface-container-low outline-none focus:ring-2 focus:ring-primary/40 placeholder:text-on-surface-variant/70"
                           />
                        </div>

                        <button
                           id="register-submit"
                           type="submit"
                           disabled={loading}
                           className="w-full py-2.5 bg-primary text-white rounded-lg font-bold hover:bg-primary-dim transition disabled:opacity-60 flex items-center justify-center gap-2"
                        >
                           {loading && <Loader2 size={18} className="animate-spin" />}
                           {loading ? "Creating Account…" : "Create Account"}
                        </button>
                        <p style={{ fontSize: "11px", color: "#888" }}>
                           This site is protected by reCAPTCHA and the Google{" "}
                           <a href="https://policies.google.com/privacy">Privacy Policy</a> and{" "}
                           <a href="https://policies.google.com/terms">Terms of Service</a> apply.
                        </p>
                     </form>
                  )}

                  {/* ================= FORGOT PASSWORD – Email ================= */}
                  {view === "forgot" && (
                     <form className="mx-auto max-w-lg space-y-5 max-[480px]:space-y-3" onSubmit={handleForgotPassword}>
                        <input
                           id="forgot-email"
                           type="email"
                           placeholder="email@example.com"
                           value={email}
                           onChange={(e) => setEmail(e.target.value)}
                           className="w-full p-2.5 rounded-lg bg-surface-container-low outline-none focus:ring-2 focus:ring-primary/40"
                        />

                        <button
                           id="forgot-submit"
                           type="submit"
                           disabled={loading}
                           className="w-full py-2.5 bg-primary text-white rounded-lg font-bold hover:bg-primary-dim transition disabled:opacity-60 flex items-center justify-center gap-2"
                        >
                           {loading && <Loader2 size={18} className="animate-spin" />}
                           {loading ? "Sending OTP…" : "Send OTP"}
                        </button>
                     </form>
                  )}

                  {/* ================= RESET PASSWORD – OTP + New Password ================= */}
                  {view === "reset-otp" && (
                     <form className="mx-auto max-w-lg space-y-5 max-[480px]:space-y-3" onSubmit={handleResetWithOtp}>
                        {/* Show the email this was sent to */}
                        <p className="text-xs max-[480px]:text-[11px] text-on-surface-variant">
                           OTP sent to <span className="font-semibold text-on-surface">{email}</span>
                        </p>

                        <input
                           id="reset-otp"
                           type="text"
                           placeholder="Enter 6-digit OTP"
                           maxLength={6}
                           value={otp}
                           onChange={(e) => setOtp(e.target.value)}
                           className="w-full p-2.5 rounded-lg bg-surface-container-low outline-none focus:ring-2 focus:ring-primary/40 tracking-widest text-center text-base"
                        />

                        <div className="relative">
                           <input
                              id="reset-new-password"
                              type={showNewPassword ? "text" : "password"}
                              placeholder="New Password"
                              value={newPassword}
                              onChange={(e) => setNewPassword(e.target.value)}
                              className="w-full p-2.5 pr-10 rounded-lg bg-surface-container-low outline-none focus:ring-2 focus:ring-primary/40"
                           />
                           <button
                              type="button"
                              onClick={() => setShowNewPassword(!showNewPassword)}
                              className="absolute right-3 top-3 text-gray-500 hover:text-gray-700"
                           >
                              {showNewPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                           </button>
                        </div>

                        <button
                           id="reset-submit"
                           type="submit"
                           disabled={loading}
                           className="w-full py-2.5 bg-primary text-white rounded-lg font-bold hover:bg-primary-dim transition disabled:opacity-60 flex items-center justify-center gap-2"
                        >
                           {loading && <Loader2 size={18} className="animate-spin" />}
                           {loading ? "Resetting…" : "Reset Password"}
                        </button>
                     </form>
                  )}

                  {/* Toggle (only for login / signup) */}
                  {(view === "login" || view === "signup") && (
                     <div className="mt-4 text-center text-sm max-[480px]:text-xs text-on-surface-variant">
                        {view === "login" ? "New user?" : "Already have an account?"}
                        <button
                           onClick={() => switchView(view === "login" ? "signup" : "login")}
                           className="ml-2 text-primary font-semibold"
                        >
                           {view === "login" ? "Create Account" : "Login"}
                        </button>
                     </div>
                  )}
               </div>

               {/* Footer */}
               <div className="mt-4 text-center text-[10px] text-on-surface-variant">
                  End-to-End Cryptographic Assurance
               </div>
            </div>
         </main>
      </div>
   );
}

export default AuthPage;
