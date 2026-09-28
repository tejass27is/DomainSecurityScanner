// Shared timezone helpers for the VAPT scheduling flows.
//
// The rule across the app: scan slots and testing windows are always stored as
// UTC-aware instants, and the zone a timestamp is *displayed* in comes from the
// viewer — a client sees their own zone, SOC/admin see IST. A stored zone is
// only ever provenance describing how a submitted wall clock was interpreted.
//
// `datetime-local` inputs hand us a zoneless wall clock (e.g. "2026-09-26T14:30"),
// so anything that submits or previews one needs the zone it will be read in.

export const SOC_TIMEZONE = "Asia/Kolkata";

// Zones offered in the pickers. This deliberately covers the regions the
// platform is used from rather than dumping all ~400 IANA zones into a native
// select; a visitor's own zone is always offered first even when it is not
// listed here.
export const COMMON_TIMEZONES = [
  "UTC",
  "Africa/Johannesburg",
  "Africa/Lagos",
  "Africa/Nairobi",
  "Africa/Cairo",
  "Africa/Casablanca",
  "Asia/Kolkata",
  "Asia/Dubai",
  "Asia/Riyadh",
  "Asia/Karachi",
  "Asia/Dhaka",
  "Asia/Manila",
  "Asia/Singapore",
  "Asia/Shanghai",
  "Asia/Tokyo",
  "Europe/London",
  "Europe/Paris",
  "Europe/Berlin",
  "America/New_York",
  "America/Chicago",
  "America/Los_Angeles",
  "America/Sao_Paulo",
  "Australia/Sydney",
];

// Legacy aliases name the same zone twice (e.g. Asia/Calcutta and Asia/Kolkata),
// which would otherwise show up as duplicate options in the pickers.
export const TIMEZONE_ALIASES = {
  "Asia/Calcutta": "Asia/Kolkata",
  "Asia/Saigon": "Asia/Ho_Chi_Minh",
  "Asia/Rangoon": "Asia/Yangon",
  "Asia/Katmandu": "Asia/Kathmandu",
  "Europe/Kiev": "Europe/Kyiv",
  "America/Buenos_Aires": "America/Argentina/Buenos_Aires",
  "US/Eastern": "America/New_York",
  "US/Central": "America/Chicago",
  "US/Mountain": "America/Denver",
  "US/Pacific": "America/Los_Angeles",
};

export function browserTimezone() {
  try {
    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    return TIMEZONE_ALIASES[zone] || zone || "UTC";
  } catch {
    return "UTC";
  }
}

// Own zone first, the rest alphabetical and fixed, so a selection never
// reshuffles the list under the user's cursor.
export function timezoneOptionsFor(ownZone = browserTimezone()) {
  return [ownZone, ...COMMON_TIMEZONES.filter((zone) => zone !== ownZone).sort()];
}

// Milliseconds to add to UTC to reach `zone` at the given UTC instant.
export function zoneOffsetMs(utcMs, zone) {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: zone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(new Date(utcMs));
  const value = (type) => Number(parts.find((part) => part.type === type)?.value);
  const asIfUtc = Date.UTC(
    value("year"),
    value("month") - 1,
    value("day"),
    value("hour"),
    value("minute"),
    value("second"),
  );
  return asIfUtc - utcMs;
}

// Resolve a zoneless `datetime-local` value against the zone it will be read in.
// Returns the matching instant, or null when the value or zone is unusable.
export function wallClockInstant(value, zone) {
  if (!value) return null;
  const [datePart = "", timePart = "00:00"] = String(value).split("T");
  const [year, month, day] = datePart.split("-").map(Number);
  const [hour, minute] = timePart.split(":").map(Number);
  if ([year, month, day, hour, minute].some((part) => !Number.isFinite(part))) return null;
  try {
    const asIfUtc = Date.UTC(year, month - 1, day, hour, minute);
    // The offset itself depends on the instant, so resolve it twice to settle
    // correctly across a DST boundary.
    let instant = asIfUtc - zoneOffsetMs(asIfUtc, zone);
    instant = asIfUtc - zoneOffsetMs(instant, zone);
    return new Date(instant);
  } catch {
    return null;
  }
}

export function formatInZone(instant, zone) {
  if (!instant || Number.isNaN(instant.getTime())) return "";
  try {
    return instant.toLocaleString("en-GB", {
      timeZone: zone,
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: true,
    });
  } catch {
    return "";
  }
}

// Render a zoneless wall clock in the SOC's clock — the reading the analyst
// will act on. Returns "" when there is nothing usable to show.
export function istLabelForWallClock(value, zone) {
  if (!value) return "";
  return formatInZone(wallClockInstant(value, zone), SOC_TIMEZONE);
}
