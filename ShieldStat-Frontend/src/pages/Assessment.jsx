import React, { useState, useMemo, useCallback, useEffect, useRef } from "react";
import { useParams, Link } from "react-router-dom";
import {
  CHECKLIST_SECTIONS,
  SECTION_MAP,
  computeSectionProgress,
  computeOverallProgress,
} from "../data/checklistData";
import { getRadarPoint, getRadarGridPoints } from "../utils/assessmentUtils";
import { getAssessment, saveAssessment } from "../services/api";

function flattenAssessmentData(data) {
  const flat = {};

  Object.values(data || {}).forEach((section) => {
    if (!section || typeof section !== "object") return;

    Object.entries(section).forEach(([key, value]) => {
      if (typeof value !== "boolean") return;

      if (key.startsWith("ignored_")) {
        const itemId = key.slice("ignored_".length);
        if (!(itemId in flat) && value) {
          flat[itemId] = false;
        }
        return;
      }

      flat[key] = value;
    });
  });

  return flat;
}

/* ═══════════════════════════════════════════════════════════════════════════
   SPIDER CHART (compact, used on overview)
   ═══════════════════════════════════════════════════════════════════════════ */

function SpiderChart({ metrics, size = 320 }) {
  const n = metrics.length;
  const maxR = 140;

  const radarPoints = useMemo(
    () =>
      metrics
        .map((m, i) =>
          getRadarPoint(Math.round((m.value / 100) * maxR), i, n, 250)
        )
        .join(" "),
    [metrics, n, maxR]
  );

  return (
    <svg
      viewBox="0 0 500 500"
      width="100%"
      height="auto"
      className="block w-full max-w-[420px] sm:max-w-[500px]"
      style={{ maxWidth: `${size}px` }}
      preserveAspectRatio="xMidYMid meet"
    >
      {/* Grid rings */}
      {[0.25, 0.5, 0.75, 1].map((scale) => (
        <polygon
          key={scale}
          points={getRadarGridPoints(Math.round(maxR * scale), n, 250)}
          fill="none"
          stroke="currentColor"
          strokeWidth={scale === 1 ? 1.5 : 0.8}
          strokeDasharray={scale < 1 ? "3 3" : "none"}
          className="text-slate-300 dark:text-slate-700"
          opacity={0.6}
        />
      ))}

      {/* Axes */}
      {metrics.map((_, i) => {
        const pt = getRadarPoint(maxR, i, n, 250);
        const [x, y] = pt.split(",").map(Number);
        return (
          <line
            key={i}
            x1={250}
            y1={250}
            x2={x}
            y2={y}
            stroke="currentColor"
            strokeWidth="0.8"
            className="text-slate-200 dark:text-slate-800"
            opacity={0.8}
          />
        );
      })}

      {/* Filled area */}
      <polygon
        points={radarPoints}
        fill="rgba(99,102,241,0.12)"
        stroke="#6366f1"
        strokeWidth="2"
        strokeLinejoin="round"
      />

      {/* Data dots */}
      {metrics.map((m, i) => {
        const r = Math.round((m.value / 100) * maxR);
        const pt = getRadarPoint(r, i, n, 250);
        const [x, y] = pt.split(",").map(Number);
        const fill =
          m.value >= 60 ? "#6366f1" : m.value >= 30 ? "#f59e0b" : "#ef4444";
        return (
          <circle
            key={i}
            cx={x}
            cy={y}
            r="4.5"
            fill={fill}
            stroke="white"
            strokeWidth="2"
            className="dark:stroke-slate-900"
          />
        );
      })}

      {/* Axis labels */}
      {metrics.map((m, i) => {
        const labelR = maxR + 32;
        const pt = getRadarPoint(labelR, i, n, 250);
        const [lx, ly] = pt.split(",").map(Number);
        const anchor = lx < 245 ? "end" : lx > 255 ? "start" : "middle";
        return (
          <text
            key={i}
            x={lx}
            y={ly + 3}
            textAnchor={anchor}
            fontSize="8.5"
            fontWeight="700"
            fontFamily="system-ui, -apple-system, sans-serif"
            className="fill-slate-500 dark:fill-slate-400"
            letterSpacing="0.5"
          >
            {m.label}
          </text>
        );
      })}
    </svg>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   CATEGORY CARD (on overview page)
   ═══════════════════════════════════════════════════════════════════════════ */

function CategoryCard({ section, progress, done, total, ignored }) {
  return (
    <Link
      to={`/assessment/${section.id}`}
      id={`cat-${section.id}`}
      className="group block rounded-2xl border border-slate-200 dark:border-slate-800/60 bg-white dark:bg-slate-900/80 hover:bg-slate-50 dark:hover:bg-slate-800/80 hover:border-indigo-200 dark:hover:border-slate-700 transition-all duration-200 overflow-hidden hover:shadow-lg hover:shadow-indigo-500/10 dark:hover:shadow-indigo-950/20"
    >
      {/* Top color accent */}
      <div className="h-1" style={{ backgroundColor: section.color }} />

      <div className="p-5">
        {/* Header */}
        <div className="flex items-start gap-3.5 mb-4">
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{
              backgroundColor: section.color + "20",
              color: section.color,
            }}
          >
            <span
              className="material-symbols-outlined text-xl"
              style={{ fontVariationSettings: '"FILL" 1' }}
            >
              {section.icon}
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="font-bold text-sm text-slate-800 dark:text-slate-100 group-hover:text-indigo-600 dark:group-hover:text-white transition-colors truncate">
              {section.label}
            </h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 line-clamp-2 leading-relaxed">
              {section.description}
            </p>
          </div>
        </div>

        {/* Progress bar */}
        <div className="h-1.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden mb-3">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${progress}%`,
              backgroundColor: section.color,
            }}
          />
        </div>

        {/* Stats row */}
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-500 dark:text-slate-400">
            {done} of {total} complete
            {ignored > 0 && (
              <span className="text-slate-400 dark:text-slate-600 ml-1">· {ignored} ignored</span>
            )}
          </span>
          <span
            className="font-black"
            style={{ color: section.color }}
          >
            {progress}%
          </span>
        </div>
      </div>
    </Link>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   OVERVIEW PAGE (main /assessment route)
   ═══════════════════════════════════════════════════════════════════════════ */

function OverviewPage({ checks }) {
  const metrics = useMemo(
    () =>
      CHECKLIST_SECTIONS.map((s) => {
        const done = s.items.filter((i) => checks[i.id] === true).length;
        const value =
          s.items.length > 0
            ? Math.round((done / s.items.length) * 100)
            : 0;
        return {
          id: s.id,
          label: s.label,
          value,
          icon: s.icon,
          color: s.color,
        };
      }),
    [checks]
  );

  const overall = useMemo(() => computeOverallProgress(checks), [checks]);
  const totalItems = CHECKLIST_SECTIONS.reduce(
    (a, s) => a + s.items.length,
    0
  );
  const totalDone = CHECKLIST_SECTIONS.reduce(
    (a, s) => a + s.items.filter((i) => checks[i.id] === true).length,
    0
  );

  return (
    <div className="min-h-screen bg-slate-100 dark:bg-slate-950">
      <div className="mx-auto max-w-[1400px] px-4 pt-6 pb-20 sm:px-6 md:pt-8">
        {/* Page Header */}
        <header className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <span
              className="material-symbols-outlined text-3xl text-indigo-600 dark:text-indigo-400"
              style={{ fontVariationSettings: '"FILL" 1' }}
            >
              verified_user
            </span>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-white">
              Security Assessment
            </h1>
          </div>
          <p className="text-slate-500 dark:text-slate-400 text-sm max-w-2xl">
            The ultimate personal security checklist to secure your digital
            life. Check off items as you complete them — your progress is saved
            automatically.
          </p>
        </header>

        {/* Top Row: Spider Chart (Left) + Category Breakdown (Right) */}
        <div className="mb-8 grid grid-cols-1 gap-8 items-stretch lg:grid-cols-2">
          {/* Spider Chart + Score */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/60 rounded-2xl p-6 shadow-sm flex flex-col items-center">
            <div className="w-full flex items-center gap-2 mb-6 pb-4 border-b border-slate-100 dark:border-slate-800/60">
              <span className="material-symbols-outlined text-indigo-600 dark:text-indigo-400 text-lg">radar</span>
              <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500">Security Profile Radar</h3>
            </div>
            <div className="w-full overflow-hidden dark:brightness-110">
              <SpiderChart metrics={metrics} size={520} />
            </div>
          </div>

          {/* Category Breakdown */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/60 rounded-2xl p-6 shadow-sm h-full">
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500 mb-4 flex items-center gap-2">
              <span className="material-symbols-outlined text-[16px]">analytics</span>
              Category Breakdown
            </div>

            {/* Simplified Overall Progress */}
            <div className="mb-8 border-b border-slate-100 dark:border-slate-800/60 pb-6">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] font-black text-slate-700 dark:text-slate-200">Overall Progress</span>
                <span className="text-[11px] font-black text-indigo-600 dark:text-indigo-400">{overall}%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                <div
                  className="h-full rounded-full bg-indigo-600 transition-all duration-1000"
                  style={{ width: `${overall}%` }}
                />
              </div>
              <div className="mt-2 text-[10px] text-slate-500 dark:text-slate-400">
                {totalDone} of {totalItems} security items completed
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-3">
              {CHECKLIST_SECTIONS.map((s) => {
                const pct = computeSectionProgress(s.id, checks);
                return (
                  <Link
                    to={`/assessment/${s.id}`}
                    key={s.id}
                    className="group flex items-center gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/50 rounded-xl px-3 py-2 -mx-3 transition-colors"
                  >
                    <span
                      className="material-symbols-outlined text-[18px]"
                      style={{ color: s.color, fontVariationSettings: '"FILL" 1' }}
                    >
                      {s.icon}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[11px] font-bold text-slate-600 dark:text-slate-300 truncate group-hover:text-indigo-600 dark:group-hover:text-slate-100">
                          {s.label}
                        </span>
                        <span className="text-[10px] font-black" style={{ color: s.color }}>
                          {pct}%
                        </span>
                      </div>
                      <div className="w-full h-1 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{ width: `${pct}%`, backgroundColor: s.color }}
                        />
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        </div>

        {/* Bottom Area: All Categories Grid */}
        <div className="mb-6 flex items-center gap-2">
          <span className="material-symbols-outlined text-indigo-600 dark:text-indigo-400 text-[20px]">grid_view</span>
          <h2 className="text-sm font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider">Security Checklists</h2>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {CHECKLIST_SECTIONS.map((section) => {
            const progress = computeSectionProgress(section.id, checks);
            const done = section.items.filter((i) => checks[i.id] === true).length;
            const ignored = section.items.filter((i) => checks[i.id] === false).length;
            return (
              <CategoryCard
                key={section.id}
                section={section}
                progress={progress}
                done={done}
                total={section.items.length}
                ignored={ignored}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   SECTION DETAIL PAGE (/assessment/:sectionId)
   ═══════════════════════════════════════════════════════════════════════════ */

function ChecklistItem({ item, checked, ignored, onToggle, onIgnore, color }) {
  return (
    <div
      className={`border-b last:border-0 border-slate-200 dark:border-slate-800/60 transition-colors ${
        ignored ? "bg-slate-50/50 dark:bg-slate-900/30" : "hover:bg-slate-50 dark:hover:bg-slate-800/30"
      }`}
    >
      <div className="grid grid-cols-1 gap-4 px-4 py-5 md:grid-cols-[96px_180px_120px_1fr] md:items-start md:gap-6 md:py-6">
        {/* Column 1: Done / Ignore */}
        <div className="flex items-center justify-between gap-4 md:flex-col md:items-center md:justify-start">
          <button
            type="button"
            onClick={() => !ignored && onToggle(item.id)}
            disabled={ignored}
            className={`w-6 h-6 rounded-lg border-2 transition-all flex items-center justify-center ${
              checked
                ? "border-transparent text-white"
                : "border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            }`}
            style={checked && !ignored ? { backgroundColor: color } : undefined}
          >
            {checked && (
              <svg viewBox="0 0 12 10" className="w-3.5 h-3 fill-none stroke-current stroke-2">
                <polyline points="1,5 4,9 11,1" />
              </svg>
            )}
          </button>

          <div className="flex flex-col items-center gap-1.5">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-600">
              Ignore
            </span>
            <button
              onClick={() => onIgnore(item.id)}
              className={`relative w-9 h-5 rounded-full transition-colors ${
                ignored ? "bg-amber-500" : "bg-slate-200 dark:bg-slate-800"
              }`}
            >
              <div
                className={`absolute top-1 left-1 w-3 h-3 rounded-full bg-white transition-transform ${
                  ignored ? "translate-x-4" : ""
                }`}
              />
            </button>
          </div>
        </div>

        {/* Column 2: Advice (Title) */}
        <div className="pt-0.5">
          <h3
            className={`text-sm font-black leading-tight transition-colors ${
              ignored
                ? "text-slate-400 dark:text-slate-600 line-through"
                : "text-slate-900 dark:text-slate-100"
            }`}
            onClick={() => !ignored && onToggle(item.id)}
          >
            {item.title}
          </h3>
        </div>

        {/* Column 3: Level */}
        <div className="pt-0.5">
          <span
            className={`text-[10px] px-3 py-1.5 rounded-full font-black uppercase tracking-widest inline-block ${
              item.level === "Essential"
                ? "bg-emerald-100/80 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-400"
                : item.level === "Optional"
                ? "bg-blue-100/80 text-blue-700 dark:bg-blue-500/20 dark:text-blue-400"
                : "bg-purple-100/80 text-purple-700 dark:bg-purple-500/20 dark:text-purple-400"
            }`}
          >
            {item.level}
          </span>
        </div>

        {/* Column 4: Details (Description) */}
        <div className="pt-0.5">
          <p
            className={`text-xs leading-relaxed transition-colors ${
              ignored ? "text-slate-400 dark:text-slate-600" : "text-slate-500 dark:text-slate-400"
            }`}
          >
            {item.description}
          </p>
        </div>
      </div>
    </div>
  );
}

function SectionDetailPage({ sectionId, checks, onToggle, onIgnore }) {
  const section = SECTION_MAP[sectionId];
  if (!section) {
    return (
      <div className="min-h-screen bg-slate-100 dark:bg-slate-950 flex items-center justify-center">
        <div className="text-center">
          <span className="material-symbols-outlined text-5xl text-slate-400 block mb-3">error</span>
          <p className="text-slate-500 dark:text-slate-400 mb-4">Section not found</p>
          <Link to="/assessment" className="text-indigo-600 dark:text-indigo-400 hover:underline font-semibold text-sm">
            ← Back to checklist
          </Link>
        </div>
      </div>
    );
  }

  const progress = computeSectionProgress(sectionId, checks);
  const doneCount = section.items.filter((i) => checks[i.id] === true).length;
  const ignoredCount = section.items.filter((i) => checks[i.id] === false).length;
  const total = section.items.length;

  const currentIndex = CHECKLIST_SECTIONS.findIndex((s) => s.id === sectionId);
  const prevSection = currentIndex > 0 ? CHECKLIST_SECTIONS[currentIndex - 1] : null;
  const nextSection = currentIndex < CHECKLIST_SECTIONS.length - 1 ? CHECKLIST_SECTIONS[currentIndex + 1] : null;

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950">
      <div className="mx-auto max-w-[1400px] px-4 py-6 sm:px-6 md:py-8">
        {/* Navigation Breadcrumb */}
        <div className="flex items-center gap-2 mb-8">
          <Link to="/assessment" className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400 hover:text-indigo-600 dark:hover:text-slate-200 text-xs font-bold transition-all">
            <span className="material-symbols-outlined text-[18px]">arrow_back</span>
            CHECKLIST
          </Link>
          <span className="text-slate-300 dark:text-slate-800">/</span>
          <span className="text-xs font-black uppercase text-slate-600 dark:text-slate-300 tracking-widest">{section.label}</span>
        </div>

        {/* Section Header */}
        <div className="mb-8 grid grid-cols-1 gap-8 items-end lg:grid-cols-[1fr_380px] xl:grid-cols-[1fr_420px]">
          <div>
            <div className="flex items-center gap-4 mb-4">
              <div className="w-14 h-14 rounded-2xl flex items-center justify-center flex-shrink-0" style={{ backgroundColor: section.color + "15", color: section.color }}>
                <span className="material-symbols-outlined text-3xl" style={{ fontVariationSettings: '"FILL" 1' }}>{section.icon}</span>
              </div>
              <h1 className="text-3xl font-black text-slate-900 dark:text-white tracking-tight">{section.label}</h1>
            </div>
            <p className="text-slate-500 dark:text-slate-400 text-sm max-w-2xl leading-relaxed">{section.description}</p>
          </div>
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/60 rounded-2xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-3 text-[11px] font-black uppercase tracking-widest">
              <span className="text-slate-400 dark:text-slate-500">Section Progress</span>
              <span style={{ color: section.color }}>{progress}%</span>
            </div>
            <div className="h-2.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden mb-3">
              <div className="h-full transition-all duration-500" style={{ width: `${progress}%`, backgroundColor: section.color }} />
            </div>
            <div className="text-[10px] font-bold text-slate-400 dark:text-slate-600">
              {doneCount} of {total} completed {ignoredCount > 0 && `· ${ignoredCount} ignored`}
            </div>
          </div>
        </div>

        {/* Checklist Table Wrapper */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/60 rounded-2xl overflow-hidden shadow-sm">
          {/* Table Header */}
          <div className="hidden bg-slate-50/80 dark:bg-slate-800/40 border-b border-slate-200 dark:border-slate-800/60 py-4 px-4 gap-6 md:grid md:grid-cols-[96px_180px_120px_1fr]">
            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400 dark:text-slate-500 text-center flex items-center justify-center gap-1">
              Done? <span className="material-symbols-outlined text-[14px]">unfold_more</span>
            </span>
            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400 dark:text-slate-500 flex items-center gap-1">
              Advice <span className="material-symbols-outlined text-[14px]">unfold_more</span>
            </span>
            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400 dark:text-slate-500 flex items-center gap-1">
              Level <span className="material-symbols-outlined text-[14px]">unfold_more</span>
            </span>
            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400 dark:text-slate-500 flex items-center gap-1">
              Details
            </span>
          </div>

          {/* Checklist Items */}
          <div className="flex flex-col">
            {section.items.map((item) => (
              <ChecklistItem key={item.id} item={item} checked={checks[item.id] === true} ignored={checks[item.id] === false} onToggle={onToggle} onIgnore={onIgnore} color={section.color} />
            ))}
          </div>
        </div>

        {/* Footer Navigation */}
        <div className="mt-12 flex flex-col gap-4 border-t border-slate-200 pt-8 dark:border-slate-800/60 sm:flex-row sm:items-center sm:justify-between">
          {prevSection ? (
            <Link to={`/assessment/${prevSection.id}`} className="group flex items-center gap-3 text-left">
              <div className="w-10 h-10 rounded-xl border border-slate-200 dark:border-slate-800/60 flex items-center justify-center group-hover:bg-slate-50 dark:group-hover:bg-slate-800 transition-colors">
                <span className="material-symbols-outlined text-slate-400 group-hover:text-indigo-600 transition-colors">arrow_back</span>
              </div>
              <div>
                <span className="text-[10px] font-black uppercase tracking-tighter text-slate-400 block mb-0.5">Previous</span>
                <span className="text-sm font-bold text-slate-700 dark:text-slate-300">{prevSection.label}</span>
              </div>
            </Link>
          ) : <div />}
          {nextSection ? (
            <Link to={`/assessment/${nextSection.id}`} className="group flex items-center gap-3 text-right">
              <div>
                <span className="text-[10px] font-black uppercase tracking-tighter text-slate-400 block mb-0.5">Next</span>
                <span className="text-sm font-bold text-slate-700 dark:text-slate-300">{nextSection.label}</span>
              </div>
              <div className="w-10 h-10 rounded-xl border border-slate-200 dark:border-slate-800/60 flex items-center justify-center group-hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors">
                <span className="material-symbols-outlined text-slate-400 group-hover:text-indigo-600 transition-colors">arrow_forward</span>
              </div>
            </Link>
          ) : <div />}
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   MAIN EXPORT — routes between Overview and Detail based on URL param
   ═══════════════════════════════════════════════════════════════════════════ */

export default function Assessment() {
  const { sectionId } = useParams();
  const [checks, setChecks] = useState({});
  const [isReady, setIsReady] = useState(false);
  const pendingChanges = useRef(new Set());

  // Fetch initial data
  useEffect(() => {
    const fetchChecks = async () => {
      const token = localStorage.getItem("token");
      if (!token) {
        setIsReady(true);
        return;
      }
      try {
        const res = await getAssessment(token);
        if (res?.data) {
          setChecks(flattenAssessmentData(res.data));
        }
      } catch (err) {
        console.error("Failed to fetch assessment data", err);
      } finally {
        setIsReady(true);
      }
    };
    fetchChecks();
  }, []);

  // Scroll to top when section changes
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, [sectionId]);

  // Debounced persist
  useEffect(() => {
    if (!isReady) return;

    const handler = setTimeout(() => {
      const token = localStorage.getItem("token");
      if (!token || pendingChanges.current.size === 0) return;

      const catMap = {
        "authentication": "authentication",
        "web-browsing": "web_browsing",
        "email": "emails",
        "messaging": "messaging",
        "social-media": "social_media",
        "networks": "networks",
        "mobile-devices": "mobile_devices",
        "personal-computers": "personal_computers",
        "smart-home": "smart_home",
        "personal-finance": "personal_finance",
        "human-aspect": "human_aspect",
        "physical-security": "physical_security"
      };

      const payload = {};
      const dirties = Array.from(pendingChanges.current);
      pendingChanges.current.clear();

      for (const sectId of dirties) {
        const section = CHECKLIST_SECTIONS.find(s => s.id === sectId);
        if (!section) continue;
        const catKey = catMap[section.id];
        payload[catKey] = {};
        for (const item of section.items) {
          if (typeof checks[item.id] === "boolean") {
            payload[catKey][item.id] = checks[item.id];
          }
        }
      }

      if (Object.keys(payload).length === 0) return;

      saveAssessment(payload, token).catch(err => {
        console.error("Failed to save assessment", err);
      });
    }, 5000);

    return () => clearTimeout(handler);
  }, [checks, isReady]);

  const toggle = useCallback((itemId) => {
    if (sectionId) pendingChanges.current.add(sectionId);
    setChecks((prev) => {
      const next = { ...prev };
      if (next[itemId] === true) {
        delete next[itemId];
      } else {
        next[itemId] = true;
      }
      return next;
    });
  }, [sectionId]);

  const ignore = useCallback((itemId) => {
    if (sectionId) pendingChanges.current.add(sectionId);
    setChecks((prev) => {
      const next = { ...prev };
      if (next[itemId] === false) {
        delete next[itemId];
      } else {
        next[itemId] = false;
      }
      return next;
    });
  }, [sectionId]);

  if (!isReady) {
    return (
      <div className="flex justify-center py-20 pb-32">
        <div className="inline-flex items-center gap-3">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-slate-300 border-t-indigo-600" />
          <p className="text-slate-500 font-medium">Loading assessment profile...</p>
        </div>
      </div>
    );
  }

  if (sectionId) {
    return (
      <SectionDetailPage
        sectionId={sectionId}
        checks={checks}
        onToggle={toggle}
        onIgnore={ignore}
      />
    );
  }

  return <OverviewPage checks={checks} />;
}
