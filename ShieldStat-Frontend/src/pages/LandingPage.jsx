// @ts-ignore
import logo from "../assets/logo.svg"
// @ts-ignore
import isecurify_logo from "../assets/isecurify_logo.png"
import { Link, useNavigate, useOutletContext } from "react-router-dom";



function LandingPage() {
   const navigate = useNavigate();
   const { isDarkMode, onToggleDarkMode } = useOutletContext();

   const handleSubmit = (event) => {
      event.preventDefault();
      navigate("/auth", { replace: true });
   }

   return (
      <div className="bg-surface text-on-surface min-h-screen flex flex-col font-body">
         {/* Navbar */}
         <header className="fixed top-0 w-full z-50 glass-nav">
            <div className="flex justify-between items-center px-8 py-4 max-w-7xl mx-auto max-[344px]:px-3 max-[344px]:py-3">
               <div className="flex items-center gap-3 max-[344px]:gap-3">
                  <img
                     src={logo}
                     alt="isecurify"
                     className="h-10 w-auto object-contain dark:invert dark:brightness-200 max-[344px]:h-8"
                  />
               </div>

               <nav className="flex items-center gap-5 max-[520px]:gap-4 max-[344px]:gap-5 sm:gap-6">
                  <button
                     type="button"
                     onClick={onToggleDarkMode}
                     className="inline-flex h-10 items-center gap-3 rounded-lg px-1.5 text-on-surface-variant transition hover:bg-surface-container-high hover:text-on-surface max-[344px]:h-9 max-[344px]:gap-2 max-[344px]:px-1"
                     aria-pressed={isDarkMode}
                     aria-label={isDarkMode ? "Switch to light mode" : "Switch to dark mode"}
                  >
                     <span
                        className="material-symbols-outlined flex h-6 w-6 shrink-0 items-center justify-center text-[22px] max-[450px]:text-[20px] leading-none"
                        aria-hidden="true"
                     >
                        {isDarkMode ? "dark_mode" : "light_mode"}
                     </span>
                     <span
                        className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ${isDarkMode ? "bg-indigo-600" : "bg-slate-200"
                           }`}
                        aria-hidden="true"
                     >
                        <span
                           className={`theme-toggle-knob absolute left-0 top-1/2 h-4 w-4 -translate-y-1/2 rounded-full bg-white transition-transform ${isDarkMode ? "translate-x-6" : "translate-x-1"
                              }`}
                        />
                     </span>
                  </button>
                  <Link to="/auth">
                     <button className="text-white editorial-gradient text-on-primary px-6 py-2.5 rounded-lg font-semibold shadow-lg hover:brightness-110 transition">
                        LOGIN
                     </button>
                  </Link>
               </nav>
            </div>
         </header>

         {/* Main */}
         <main className="flex-grow flex flex-col items-center justify-center px-6 pt-24">
            {/* Icon */}
            <div className="mb-12 relative">
               <div className="absolute inset-0 bg-gray-500 blur-3xl rounded-full scale-150"></div>

               <div className="bg-white relative w-16 h-16 rounded-full flex items-center justify-center pulse-glow">
                  <img
                     src={isecurify_logo}
                     alt="Company Logo"
                     className="rounded-xl h-12 w-auto object-contain"
                  />
               </div>
            </div>

            {/* Heading */}
            <div className="text-center mb-10">
               <h1 className="font-headline text-5xl md:text-6xl font-extrabold tracking-tight mb-4">
                  Audit your domain.
               </h1>

               <p className="text-on-surface-variant text-lg max-w-md mx-auto">
                  A clean, comprehensive security analysis for your digital
                  infrastructure. No noise. Just intelligence.
               </p>
            </div>

            {/* Input */}
            <div className="w-full max-w-2xl">
               <form className="relative group" onSubmit={handleSubmit}>
                  <div className="absolute -inset-1 bg-gradient-to-r from-primary/10 to-tertiary/10 rounded-2xl blur opacity-25 group-focus-within:opacity-100 transition duration-1000"></div>

                  <div className="relative bg-surface-container-lowest rounded-2xl p-2 shadow-sm border border-outline-variant/10 focus-within:border-primary/20 max-[520px]:w-full">
                     <div className="flex flex-wrap items-center gap-2">
                        <div className="flex flex-shrink-0 items-center pl-6 text-on-surface-variant/40">
                           <span className="material-symbols-outlined text-2xl max-[450px]:text-xl">
                              language
                           </span>
                        </div>

                        <input
                           name="domain_input_field"
                           type="text"
                           placeholder="example.com"
                           className="landing-domain-input min-w-0 flex-1 bg-transparent outline-none px-4 py-4 text-xl font-medium placeholder:text-on-surface-variant/30"
                        />

                        <button
                           type="submit"
                           className="w-full sm:w-auto justify-center text-white editorial-gradient text-on-primary px-8 py-4 rounded-xl font-bold text-lg flex items-center gap-2 hover:brightness-110 transition max-[552px]:px-4"
                        >
                           Start Scan
                           <span className="material-symbols-outlined">arrow_forward</span>
                        </button>
                     </div>
                  </div>
               </form>
            </div>

            {/* Tags */}
            <div className="mt-8 flex gap-8 items-center justify-center flex-wrap">
               <div className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
                  <span className="text-on-surface-variant text-sm font-semibold tracking-widest uppercase">
                     SSL Protocol
                  </span>
               </div>

               <div className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
                  <span className="text-on-surface-variant text-sm font-semibold tracking-widest uppercase">
                     DNS Integrity
                  </span>
               </div>

               <div className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
                  <span className="text-on-surface-variant text-sm font-semibold tracking-widest uppercase">
                     Threat Intel
                  </span>
               </div>
            </div>
         </main>
      </div>
   );
}

export default LandingPage
