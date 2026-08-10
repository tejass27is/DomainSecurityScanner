import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Loader2, CheckCircle2, XCircle } from "lucide-react";
import { verifyEmail } from "../services/api";
// @ts-ignore
import isecurify_logo from "../assets/isecurify_logo.png";

function VerifyEmailPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");

  const [status, setStatus] = useState("loading");
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setMessage("This verification link is invalid or incomplete.");
      return;
    }

    let cancelled = false;
    (async () => {
      try {
        const data = await verifyEmail(token);
        if (!cancelled) {
          setStatus("success");
          setMessage(data.message || "Your email is verified. You can now log in.");
        }
      } catch (err) {
        if (!cancelled) {
          setStatus("error");
          setMessage(err.message || "Verification failed.");
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <div className="max-h-full flex min-h-screen flex-col bg-background-light font-body">
      <main className="flex flex-grow items-center justify-center px-6 py-12">
        <div className="w-full max-w-lg">
          <div className="mb-10 text-center">
            <div className="mb-6 flex justify-center">
              <div className="rounded-xl bg-white p-4 shadow dark:bg-slate-800">
                <img
                  src={isecurify_logo}
                  alt="isecurify"
                  className="h-12 w-auto rounded-xl object-contain dark:invert dark:brightness-200"
                />
              </div>
            </div>
            <h1 className="font-headline text-4xl font-extrabold text-on-surface">
              Domain Security Scanner
            </h1>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-8 shadow md:p-10">
            <h2 className="mb-2 text-center text-2xl font-bold text-on-surface">Email verification</h2>

            {status === "loading" && (
              <div className="flex flex-col items-center gap-4 py-8 text-on-surface-variant">
                <Loader2 className="h-10 w-10 animate-spin text-primary" />
                <p className="text-sm">Confirming your email…</p>
              </div>
            )}

            {status === "success" && (
              <div className="space-y-4">
                <div className="flex justify-center">
                  <CheckCircle2 className="h-14 w-14 text-emerald-600" strokeWidth={1.75} />
                </div>
                <p className="text-center text-on-surface">{message}</p>
                <Link
                  to="/auth"
                  className="mt-4 block w-full rounded-lg bg-primary py-3 text-center font-bold text-white transition hover:bg-primary-dim"
                >
                  Go to sign in
                </Link>
              </div>
            )}

            {status === "error" && (
              <div className="space-y-4">
                <div className="flex justify-center">
                  <XCircle className="h-14 w-14 text-rose-500" strokeWidth={1.75} />
                </div>
                <p className="rounded-lg border border-red-200 bg-red-50 p-3 text-center text-sm text-red-700">
                  {message}
                </p>
                <Link
                  to="/auth"
                  className="mt-2 block w-full rounded-lg border border-slate-200 py-3 text-center font-semibold text-on-surface transition hover:bg-surface-container-low"
                >
                  Back to sign in
                </Link>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

export default VerifyEmailPage;
