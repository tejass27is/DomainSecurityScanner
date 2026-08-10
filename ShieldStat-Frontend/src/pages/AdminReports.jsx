import ReportedIssuesPanel from "../components/ReportedIssuesPanel";

export default function AdminReports() {
  return (
    <div className="min-h-screen bg-surface px-4 py-6 sm:px-6 lg:px-8">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <section className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.3em] text-primary">Reported Issues</p>
              <h2 className="text-2xl font-black tracking-tight text-on-surface sm:text-3xl">
                Review flagged scan findings from users
              </h2>
              <p className="mt-2 max-w-2xl text-sm text-slate-600">
                Analyze and triage reported security issues submitted by users.
              </p>
            </div>
          </div>
        </section>

        <ReportedIssuesPanel />
      </div>
    </div>
  );
}
