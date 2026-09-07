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
      height="100%"
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
        fill="rgba(128,0,128,0.12)"
        stroke="#800080"
        strokeWidth="2"
        strokeLinejoin="round"
      />

      {/* Data dots */}
      {metrics.map((m, i) => {
        const r = Math.round((m.value / 100) * maxR);
        const pt = getRadarPoint(r, i, n, 250);
        const [x, y] = pt.split(",").map(Number);
        const fill =
          m.value >= 60 ? "#800080" : m.value >= 30 ? "#f59e0b" : "#ef4444";
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
      className="group block overflow-hidden rounded-3xl border border-slate-200/80 bg-white/90 shadow-[0_12px_40px_rgba(15,23,42,0.06)] backdrop-blur-sm transition-all duration-200 hover:border-purple-200 hover:shadow-[0_20px_50px_rgba(128,0,128,0.15)] dark:border-slate-800 dark:bg-slate-900/80 dark:hover:border-purple-800"
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
    <div className="min-h-full space-y-8">
      <div className="mx-auto max-w-[1400px]">
        {/* Page Header */}
        <header className="mb-8 rounded-[2rem] border border-slate-200/70 bg-gradient-to-br from-purple-600 to-indigo-600 p-6 text-white shadow-[0_20px_60px_rgba(15,23,42,0.08)] sm:p-8">
          <div className="flex flex-wrap items-center gap-3 mb-3">
            <span
              className="material-symbols-outlined text-3xl"
              style={{ fontVariationSettings: '"FILL" 1' }}
            >
              verified_user
            </span>
            <h1 className="text-2xl font-extrabold tracking-tight sm:text-3xl">
              Security Assessment
            </h1>
          </div>
          <p className="max-w-2xl text-sm text-purple-50 sm:text-base">
            The ultimate personal security checklist to secure your digital
            life. Check off items as you complete them — your progress is saved
            automatically.
          </p>
        </header>

        {/* Top Row: Spider Chart (Left) + Category Breakdown (Right) */}
        <div className="mb-8 grid grid-cols-1 gap-8 items-stretch lg:grid-cols-2">
          {/* Spider Chart + Score */}
          <div className="app-card-surface flex flex-col items-center p-6">
            <div className="w-full flex items-center gap-2 mb-6 pb-4 border-b border-slate-100 dark:border-slate-800/60">
              <span className="material-symbols-outlined text-indigo-600 dark:text-indigo-400 text-lg">radar</span>
              <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500">Security Profile Radar</h3>
            </div>
            <div className="w-full overflow-hidden dark:brightness-110">
              <SpiderChart metrics={metrics} size={520} />
            </div>
          </div>

          {/* Category Breakdown */}
          <div className="app-card-surface h-full p-6">
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
                  className="h-full rounded-full bg-purple-600 transition-all duration-1000"
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
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className={`group border border-slate-200/70 dark:border-slate-800/60 rounded-2xl transition-all duration-200 ${
        ignored
          ? "bg-slate-50/40 dark:bg-slate-900/20 opacity-60"
          : checked
          ? "bg-white/80 dark:bg-slate-900/60 border-l-2 shadow-[0_2px_12px_rgba(128,0,128,0.06)]"
          : "bg-white/60 dark:bg-slate-900/40 hover:shadow-[0_4px_20px_rgba(15,23,42,0.06)] hover:border-slate-300/80 dark:hover:border-slate-700"
      }`}
      style={checked && !ignored ? { borderLeftColor: color, borderLeftWidth: "3px" } : undefined}
    >
      <div className="px-4 py-3.5 sm:px-5 sm:py-4">
        {/* Top Row: Checkbox + Title + Level + Ignore + Expand */}
        <div className="flex items-center gap-3">
          {/* Checkbox */}
          <button
            type="button"
            onClick={() => !ignored && onToggle(item.id)}
            disabled={ignored}
            className={`w-5 h-5 sm:w-6 sm:h-6 rounded-lg border-2 transition-all duration-200 flex items-center justify-center flex-shrink-0 ${
              checked
                ? "border-transparent text-white shadow-sm"
                : "border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 group-hover:border-slate-400 dark:group-hover:border-slate-600"
            }`}
            style={checked && !ignored ? { backgroundColor: color } : undefined}
          >
            {checked && (
              <svg viewBox="0 0 12 10" className="w-3 h-2.5 fill-none stroke-current stroke-2.5">
                <polyline points="1,5 4,9 11,1" />
              </svg>
            )}
          </button>

          {/* Title */}
          <h3
            className={`text-[13px] sm:text-sm font-bold leading-snug transition-colors flex-1 min-w-0 ${
              ignored
                ? "text-slate-400 dark:text-slate-600 line-through"
                : "text-slate-800 dark:text-slate-100"
            }`}
            onClick={() => !ignored && onToggle(item.id)}
          >
            {item.title}
          </h3>

          {/* Level Badge */}
          <span
            className={`text-[9px] sm:text-[10px] px-2.5 py-1 rounded-full font-bold uppercase tracking-wider flex-shrink-0 ${
              item.level === "Essential"
                ? "bg-emerald-100/80 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400"
                : item.level === "Optional"
                ? "bg-blue-100/80 text-blue-700 dark:bg-blue-500/15 dark:text-blue-400"
                : "bg-purple-100/80 text-purple-700 dark:bg-purple-500/15 dark:text-purple-400"
            }`}
          >
            {item.level}
          </span>

          {/* Ignore Toggle */}
          <button
            onClick={() => onIgnore(item.id)}
            className={`relative w-8 h-[18px] sm:w-9 sm:h-5 rounded-full transition-colors flex-shrink-0 ${
              ignored ? "bg-amber-400 dark:bg-amber-500" : "bg-slate-200 dark:bg-slate-800 group-hover:bg-slate-300 dark:group-hover:bg-slate-700"
            }`}
          >
            <div
              className={`absolute top-[2px] left-[2px] w-3.5 h-3.5 sm:w-4 sm:h-4 rounded-full bg-white transition-transform duration-200 shadow-sm ${
                ignored ? "translate-x-[14px] sm:translate-x-[16px]" : ""
              }`}
            />
          </button>

          {/* Expand/Collapse */}
          <button
            onClick={() => setExpanded(!expanded)}
            className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg flex items-center justify-center text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all flex-shrink-0"
          >
            <span
              className="material-symbols-outlined text-[18px] transition-transform duration-200"
              style={{ transform: expanded ? "rotate(180deg)" : "rotate(0deg)" }}
            >
              expand_more
            </span>
          </button>
        </div>

        {/* Expandable Description */}
        <div
          className={`overflow-hidden transition-all duration-300 ease-in-out ${
            expanded ? "max-h-[600px] opacity-100 mt-3" : "max-h-0 opacity-0 mt-0"
          }`}
        >
          <div className="pl-8 sm:pl-9 border-l-2 border-slate-200/60 dark:border-slate-800/60 ml-0">
            <p
              className={`text-xs sm:text-[13px] leading-relaxed ${
                ignored ? "text-slate-400 dark:text-slate-600" : "text-slate-500 dark:text-slate-400"
              }`}
            >
              {item.description}
            </p>
          </div>
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

  const essentialItems = section.items.filter((i) => i.level === "Essential");
  const optionalItems = section.items.filter((i) => i.level === "Optional");
  const recommendedItems = section.items.filter((i) => i.level !== "Essential" && i.level !== "Optional");

  const currentIndex = CHECKLIST_SECTIONS.findIndex((s) => s.id === sectionId);
  const prevSection = currentIndex > 0 ? CHECKLIST_SECTIONS[currentIndex - 1] : null;
  const nextSection = currentIndex < CHECKLIST_SECTIONS.length - 1 ? CHECKLIST_SECTIONS[currentIndex + 1] : null;

  return (
    <div className="min-h-full">
      <div className="mx-auto max-w-[1400px]">

        {/* Navigation Breadcrumb */}
        <div className="flex items-center gap-2 mb-6">
          <Link to="/assessment" className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400 hover:text-indigo-600 dark:hover:text-slate-200 text-xs font-bold transition-all">
            <span className="material-symbols-outlined text-[18px]">arrow_back</span>
            CHECKLIST
          </Link>
          <span className="text-slate-300 dark:text-slate-800">/</span>
          <span className="text-xs font-black uppercase text-slate-600 dark:text-slate-300 tracking-widest">{section.label}</span>
        </div>

        {/* Sticky Progress Header */}
        <div className="sticky top-0 z-30 -mx-4 sm:mx-0 px-4 sm:px-0 pb-4 pt-1">
          <div className="rounded-2xl border border-slate-200/60 dark:border-slate-800/60 bg-white/90 dark:bg-slate-900/90 backdrop-blur-xl shadow-[0_4px_24px_rgba(15,23,42,0.06)] dark:shadow-[0_4px_24px_rgba(0,0,0,0.3)] p-4 sm:p-5">
            <div className="flex items-center gap-4 mb-3">
              <div className="w-10 h-10 sm:w-12 sm:h-12 rounded-xl flex items-center justify-center flex-shrink-0" style={{ backgroundColor: section.color + "18", color: section.color }}>
                <span className="material-symbols-outlined text-xl sm:text-2xl" style={{ fontVariationSettings: '"FILL" 1' }}>{section.icon}</span>
              </div>
              <div className="flex-1 min-w-0">
                <h1 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white tracking-tight truncate">{section.label}</h1>
                <p className="text-slate-500 dark:text-slate-400 text-xs sm:text-sm leading-relaxed line-clamp-1 mt-0.5">{section.description}</p>
              </div>
              <div className="text-right flex-shrink-0">
                <div className="text-2xl sm:text-3xl font-black" style={{ color: section.color }}>{progress}%</div>
                <div className="text-[10px] font-bold text-slate-400 dark:text-slate-600">
                  {doneCount}/{total} done
                  {ignoredCount > 0 && <span className="text-slate-300 dark:text-slate-700"> · {ignoredCount} ign</span>}
                </div>
              </div>
            </div>
            <div className="h-2 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
              <div className="h-full rounded-full transition-all duration-500" style={{ width: `${progress}%`, backgroundColor: section.color }} />
            </div>
          </div>
        </div>

        {/* Checklist Grid — 1-col on mobile, 2-col on laptop+ */}
        <div className="mt-2">
          {/* Essential Items */}
          {essentialItems.length > 0 && (
            <div className="mb-8">
              <div className="flex items-center gap-2 mb-4">
                <div className="w-2 h-2 rounded-full bg-emerald-500" />
                <h2 className="text-xs font-bold text-emerald-700 dark:text-emerald-400 uppercase tracking-widest">Essential</h2>
                <span className="text-[10px] font-bold text-slate-400 dark:text-slate-600">({essentialItems.length})</span>
              </div>
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                {essentialItems.map((item) => (
                  <ChecklistItem key={item.id} item={item} checked={checks[item.id] === true} ignored={checks[item.id] === false} onToggle={onToggle} onIgnore={onIgnore} color={section.color} />
                ))}
              </div>
            </div>
          )}

          {/* Recommended Items */}
          {recommendedItems.length > 0 && (
            <div className="mb-8">
              <div className="flex items-center gap-2 mb-4">
                <div className="w-2 h-2 rounded-full bg-purple-500" />
                <h2 className="text-xs font-bold text-purple-700 dark:text-purple-400 uppercase tracking-widest">Recommended</h2>
                <span className="text-[10px] font-bold text-slate-400 dark:text-slate-600">({recommendedItems.length})</span>
              </div>
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                {recommendedItems.map((item) => (
                  <ChecklistItem key={item.id} item={item} checked={checks[item.id] === true} ignored={checks[item.id] === false} onToggle={onToggle} onIgnore={onIgnore} color={section.color} />
                ))}
              </div>
            </div>
          )}

          {/* Optional Items */}
          {optionalItems.length > 0 && (
            <div className="mb-8">
              <div className="flex items-center gap-2 mb-4">
                <div className="w-2 h-2 rounded-full bg-blue-500" />
                <h2 className="text-xs font-bold text-blue-700 dark:text-blue-400 uppercase tracking-widest">Optional</h2>
                <span className="text-[10px] font-bold text-slate-400 dark:text-slate-600">({optionalItems.length})</span>
              </div>
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                {optionalItems.map((item) => (
                  <ChecklistItem key={item.id} item={item} checked={checks[item.id] === true} ignored={checks[item.id] === false} onToggle={onToggle} onIgnore={onIgnore} color={section.color} />
                ))}
              </div>
            </div>
          )}
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
        <div className="app-card-surface inline-flex items-center gap-3 px-6 py-4">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-slate-300 border-t-indigo-600" />
          <p className="font-medium text-slate-600 dark:text-slate-300">Loading assessment profile...</p>
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
