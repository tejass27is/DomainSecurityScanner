import {
  CartesianGrid,
  LabelList,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

function formatScoreLabel(value) {
  const numericValue = Number(value ?? 0);
  return Number.isInteger(numericValue) ? String(numericValue) : numericValue.toFixed(1);
}

function renderScoreLabel({ x, y, value }) {
  if (value === undefined || value === null) return null;

  return (
    <text
      x={x}
      y={y - 10}
      textAnchor="middle"
      fill="#4f46e5"
      fontSize="10"
      fontWeight="700"
    >
      {`${formatScoreLabel(value)}/100`}
    </text>
  );
}

function ScanTrendChart({ trendData, selectedDomain }) {
  return (
    <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={220}>
      <LineChart data={trendData} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <CartesianGrid stroke="#e2e8f0" strokeDasharray="4 4" />
        <XAxis dataKey="label" tickLine={false} axisLine={false} tick={{ fill: "#4f46e5", fontSize: 12 }} />
        <YAxis domain={[0, 100]} tickLine={false} axisLine={false} tick={{ fill: "#64748b", fontSize: 12 }} />
        <Tooltip
          trigger="click"
          formatter={(value, name, item) => {
            const score = Number(item?.payload?.score ?? value ?? 0);
            return [
              `${formatScoreLabel(score)} / 100`,
              item?.payload?.domain ? `${item.payload.domain} score` : name,
            ];
          }}
          labelFormatter={(label, payload) => {
            const point = payload?.[0]?.payload;
            return point?.fullLabel ? `Scan date: ${point.fullLabel}` : `Scan: ${label}`;
          }}
          contentStyle={{ borderRadius: 12, borderColor: "#c7d2fe", boxShadow: "0 10px 30px rgba(79, 70, 229, 0.12)" }}
          labelStyle={{ color: "#4f46e5", fontWeight: 700 }}
          itemStyle={{ color: "#0f172a" }}
        />
        <Legend wrapperStyle={{ fontSize: "12px" }} />
        <Line
          type="monotone"
          dataKey="score"
          stroke="#4f46e5"
          strokeWidth={3}
          dot={{ r: 5, fill: "#4f46e5", strokeWidth: 2, stroke: "#ffffff" }}
          activeDot={{ r: 7, fill: "#312e81", stroke: "#c7d2fe", strokeWidth: 2 }}
          name={selectedDomain === "All Domains" ? "Security score" : selectedDomain}
        >
          <LabelList
            dataKey="score"
            position="top"
            offset={8}
            content={renderScoreLabel}
          />
        </Line>
      </LineChart>
    </ResponsiveContainer>
  );
}

export default ScanTrendChart;
