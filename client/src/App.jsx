import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";
import { io } from "socket.io-client";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Database,
  Globe,
  Shield,
  ShieldAlert,
  Terminal,
  Wifi,
  XCircle,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const API_URL =
  import.meta.env.VITE_API_URL || "http://localhost:5000";

const api = axios.create({
  baseURL: API_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

const initialRequest = {
  method: "GET",
  endpoint: "/api/users",
  payload: "",
  ipAddress: "192.168.1.50",
};

function App() {
  const [events, setEvents] = useState([]);
  const [backendOnline, setBackendOnline] = useState(false);
  const [socketConnected, setSocketConnected] = useState(false);
  const [loadingEvents, setLoadingEvents] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [requestData, setRequestData] = useState(initialRequest);
const [lastAnalysis, setLastAnalysis] = useState(null);
const [liveAlert, setLiveAlert] = useState(null);
const [error, setError] = useState("");

  const fetchHealth = useCallback(async () => {
    try {
      await api.get("/api/health");
      setBackendOnline(true);
    } catch {
      setBackendOnline(false);
    }
  }, []);

  const fetchEvents = useCallback(async () => {
    try {
      const response = await api.get("/api/security/events?limit=100");

      if (response.data?.success) {
        setEvents(response.data.events || []);
      }

      setError("");
    } catch (err) {
      console.error("Failed to fetch security events:", err);
      setError("Unable to load security events.");
    } finally {
      setLoadingEvents(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    fetchEvents();

    const healthInterval = setInterval(fetchHealth, 5000);

    const socket = io(API_URL, {
      transports: ["websocket", "polling"],
    });

    socket.on("connect", () => {
      console.log("SentinelAPI realtime connection established");
      setSocketConnected(true);
    });

    socket.on("disconnect", () => {
      console.log("SentinelAPI realtime connection closed");
      setSocketConnected(false);
    });

    socket.on("connect_error", (socketError) => {
      console.error("Socket connection error:", socketError.message);
      setSocketConnected(false);
    });

    socket.on("security-event", (newEvent) => {
  console.log("LIVE SECURITY EVENT:", newEvent);

  const normalizedEvent = {
    ...newEvent,
    _id: newEvent.id || newEvent._id,
  };

  setLiveAlert(normalizedEvent);

  setEvents((currentEvents) => {
    const eventId = String(
      normalizedEvent._id || normalizedEvent.id
    );

    const alreadyExists = currentEvents.some(
      (event) =>
        String(event._id || event.id) === eventId
    );

    if (alreadyExists) {
      return currentEvents;
    }

    return [
      normalizedEvent,
      ...currentEvents,
    ].slice(0, 100);
  });

  setTimeout(() => {
    setLiveAlert((current) => {
      if (
        current &&
        String(current._id || current.id) ===
          String(normalizedEvent._id || normalizedEvent.id)
      ) {
        return null;
      }

      return current;
    });
  }, 5000);
});
    

    return () => {
      clearInterval(healthInterval);
      socket.disconnect();
    };
  }, [fetchHealth, fetchEvents]);

  const handleRequestChange = (event) => {
    const { name, value } = event.target;

    setRequestData((current) => ({
      ...current,
      [name]: value,
    }));
  };

  const analyzeRequest = async (event) => {
    event.preventDefault();

    setAnalyzing(true);
    setError("");
    setLastAnalysis(null);

    try {
      const response = await api.post(
        "/api/security/analyze",
        requestData
      );

      if (response.data?.success) {
        setLastAnalysis(response.data);

        if (!response.data.detected) {
          await fetchEvents();
        }
      }
    } catch (err) {
      console.error("Analysis failed:", err);

      setError(
        err.response?.data?.message ||
          "Unable to connect to SentinelAPI."
      );
    } finally {
      setAnalyzing(false);
    }
  };

  const statistics = useMemo(() => {
    const critical = events.filter(
      (event) => event.severity === "CRITICAL"
    ).length;

    const high = events.filter(
      (event) => event.severity === "HIGH"
    ).length;

    const medium = events.filter(
      (event) => event.severity === "MEDIUM"
    ).length;

    const low = events.filter(
      (event) => event.severity === "LOW"
    ).length;

    const averageRisk =
      events.length > 0
        ? Math.round(
            events.reduce(
              (total, event) =>
                total + Number(event.riskScore || 0),
              0
            ) / events.length
          )
        : 0;

    return {
      total: events.length,
      critical,
      high,
      medium,
      low,
      averageRisk,
    };
  }, [events]);

  const chartData = useMemo(() => {
    const grouped = {};

    [...events].reverse().forEach((event) => {
      const date = new Date(
        event.timestamp || event.createdAt
      );

      if (Number.isNaN(date.getTime())) {
        return;
      }

      const label = date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });

      if (!grouped[label]) {
        grouped[label] = {
          time: label,
          risk: 0,
          attacks: 0,
        };
      }

      grouped[label].risk = Math.max(
        grouped[label].risk,
        Number(event.riskScore || 0)
      );

      grouped[label].attacks += 1;
    });

    return Object.values(grouped).slice(-12);
  }, [events]);

  const severityClass = (severity) => {
    switch (severity) {
      case "CRITICAL":
        return "border-red-500/20 bg-red-500/10 text-red-400";

      case "HIGH":
        return "border-orange-500/20 bg-orange-500/10 text-orange-400";

      case "MEDIUM":
        return "border-yellow-500/20 bg-yellow-500/10 text-yellow-400";

      default:
        return "border-cyan-500/20 bg-cyan-500/10 text-cyan-400";
    }
  };

  const typeLabel = (type) => {
    if (!type) return "UNKNOWN";

    return type.replaceAll("_", " ");
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">

      {/* HEADER */}

      <header className="sticky top-0 z-50 border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between px-6 py-4">

          <div className="flex items-center gap-3">

            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-500/10 ring-1 ring-cyan-400/20">
              <Shield className="h-6 w-6 text-cyan-400" />
            </div>

            <div>
              <h1 className="text-xl font-bold">
                Sentinel<span className="text-cyan-400">API</span>
              </h1>

              <p className="text-xs text-slate-500">
                API Threat Detection Platform
              </p>
            </div>

          </div>

          <div className="flex items-center gap-3">

            <div className="hidden items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs text-slate-400 sm:flex">
              <Wifi className="h-3.5 w-3.5" />
              Realtime monitoring
            </div>

            <div
              className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium ${
                backendOnline
                  ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                  : "border-red-500/20 bg-red-500/10 text-red-400"
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${
                  backendOnline
                    ? "animate-pulse bg-emerald-400"
                    : "bg-red-400"
                }`}
              />

              {backendOnline
                ? "Backend Online"
                : "Backend Offline"}
            </div>

          </div>

        </div>
      </header>

      <main className="mx-auto max-w-[1600px] px-6 py-8">

        {liveAlert && (
  <div className="fixed right-6 top-24 z-[100] w-[360px] rounded-2xl border border-red-500/30 bg-slate-900 p-5 shadow-2xl shadow-red-950/40">
    <div className="flex items-start gap-4">
      <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-red-500/10">
        <AlertTriangle className="h-6 w-6 text-red-400" />
      </div>

      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 animate-pulse rounded-full bg-red-400" />

          <p className="text-xs font-semibold uppercase tracking-wider text-red-400">
            Live Threat Detected
          </p>
        </div>

        <h3 className="mt-2 text-lg font-bold text-slate-100">
          {typeLabel(liveAlert.type)}
        </h3>

        <div className="mt-2 flex items-center gap-2">
          <span
            className={`rounded-md border px-2 py-1 text-xs font-semibold ${severityClass(
              liveAlert.severity
            )}`}
          >
            {liveAlert.severity}
          </span>

          <span className="text-xs text-slate-500">
            Risk {liveAlert.riskScore}/100
          </span>
        </div>

        <p className="mt-3 text-xs text-slate-400">
          {liveAlert.description}
        </p>

        <p className="mt-2 text-xs text-slate-600">
          IP: {liveAlert.ipAddress}
        </p>
      </div>
    </div>
  </div>
)}

        {/* TITLE */}

        <section className="mb-8">

          <div className="flex flex-col justify-between gap-4 md:flex-row md:items-end">

            <div>

              <div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-[0.2em] text-cyan-400">
                <Activity className="h-4 w-4" />
                Security Operations Center
              </div>

              <h2 className="text-3xl font-bold tracking-tight md:text-4xl">
                Threat Detection Dashboard
              </h2>

              <p className="mt-2 max-w-2xl text-sm text-slate-400">
                Monitor API traffic, detect malicious request
                patterns and analyze security threats in real time.
              </p>

            </div>

            <div className="flex items-center gap-2 text-xs text-slate-500">
              <Clock3 className="h-4 w-4" />
              Live monitoring
            </div>

          </div>

        </section>

        {/* ERROR */}

        {error && (
          <div className="mb-6 flex items-center gap-3 rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            <XCircle className="h-5 w-5" />
            {error}
          </div>
        )}

        {/* STATISTICS */}

        <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">

          <StatCard
            title="Total Threats"
            value={statistics.total}
            icon={ShieldAlert}
            description="Detected security events"
          />

          <StatCard
            title="Critical"
            value={statistics.critical}
            icon={AlertTriangle}
            description="Immediate attention"
            danger
          />

          <StatCard
            title="High Risk"
            value={statistics.high}
            icon={ShieldAlert}
            description="Requires investigation"
          />

          <StatCard
            title="Medium / Low"
            value={statistics.medium + statistics.low}
            icon={Activity}
            description="Lower severity events"
          />

          <StatCard
            title="Average Risk"
            value={`${statistics.averageRisk}/100`}
            icon={Database}
            description="Across all threats"
          />

        </section>

        {/* CHART + STATUS */}

        <section className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-3">

          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 xl:col-span-2">

            <div className="mb-6 flex items-center justify-between">

              <div>
                <h3 className="font-semibold">
                  Threat Activity
                </h3>

                <p className="mt-1 text-xs text-slate-500">
                  Live risk score activity
                </p>
              </div>

              <div className="flex items-center gap-2 text-xs text-cyan-400">
                <span className="h-2 w-2 rounded-full bg-cyan-400" />
                Risk score
              </div>

            </div>

            <div className="h-[300px]">

              {chartData.length > 0 ? (

                <ResponsiveContainer
                  width="100%"
                  height="100%"
                >
                  <AreaChart data={chartData}>

                    <defs>
                      <linearGradient
                        id="riskGradient"
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="1"
                      >
                        <stop
                          offset="0%"
                          stopColor="#22d3ee"
                          stopOpacity={0.35}
                        />

                        <stop
                          offset="100%"
                          stopColor="#22d3ee"
                          stopOpacity={0}
                        />
                      </linearGradient>
                    </defs>

                    <CartesianGrid
                      stroke="#1e293b"
                      strokeDasharray="3 3"
                    />

                    <XAxis
                      dataKey="time"
                      stroke="#64748b"
                      fontSize={11}
                    />

                    <YAxis
                      domain={[0, 100]}
                      stroke="#64748b"
                      fontSize={11}
                    />

                    <Tooltip
                      contentStyle={{
                        background: "#0f172a",
                        border: "1px solid #334155",
                        borderRadius: "10px",
                        color: "#e2e8f0",
                      }}
                    />

                    <Area
                      type="monotone"
                      dataKey="risk"
                      stroke="#22d3ee"
                      strokeWidth={2}
                      fill="url(#riskGradient)"
                    />

                  </AreaChart>
                </ResponsiveContainer>

              ) : (

                <div className="flex h-full flex-col items-center justify-center text-center">

                  <Activity className="mb-3 h-10 w-10 text-slate-700" />

                  <p className="text-sm text-slate-500">
                    No threat activity yet
                  </p>

                  <p className="mt-1 text-xs text-slate-600">
                    Analyze a request to generate security data.
                  </p>

                </div>

              )}

            </div>

          </div>

          {/* STATUS */}

          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">

            <h3 className="font-semibold">
              System Status
            </h3>

            <p className="mt-1 text-xs text-slate-500">
              SentinelAPI infrastructure
            </p>

            <div className="mt-6 space-y-3">

              <StatusRow
                name="API Server"
                status={
                  backendOnline
                    ? "Operational"
                    : "Offline"
                }
                online={backendOnline}
              />

              <StatusRow
                name="MongoDB"
                status={
                  backendOnline
                    ? "Connected"
                    : "Unknown"
                }
                online={backendOnline}
              />

              <StatusRow
                name="Threat Engine"
                status="Active"
                online
              />

              <StatusRow
                name="Realtime Socket"
                status={
                  socketConnected
                    ? "Connected"
                    : "Disconnected"
                }
                online={socketConnected}
              />

            </div>

            <div className="mt-6 rounded-xl border border-cyan-500/10 bg-cyan-500/5 p-4">

              <div className="flex items-center gap-3">

                <CheckCircle2 className="h-5 w-5 text-cyan-400" />

                <div>

                  <p className="text-sm font-medium">
                    Protection active
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    Threat analysis engine is ready.
                  </p>

                </div>

              </div>

            </div>

          </div>

        </section>

        {/* ANALYZER */}

        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-5">

          <div className="mb-6">

            <div className="flex items-center gap-3">

              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-purple-500/10">
                <Terminal className="h-5 w-5 text-purple-400" />
              </div>

              <div>

                <h3 className="font-semibold">
                  Request Analyzer
                </h3>

                <p className="text-xs text-slate-500">
                  Test an API request against the detection engine.
                </p>

              </div>

            </div>

          </div>

          <form onSubmit={analyzeRequest}>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">

              <InputField
                label="HTTP Method"
                name="method"
                value={requestData.method}
                onChange={handleRequestChange}
                placeholder="GET"
              />

              <InputField
                label="Endpoint"
                name="endpoint"
                value={requestData.endpoint}
                onChange={handleRequestChange}
                placeholder="/api/users"
              />

              <InputField
                label="IP Address"
                name="ipAddress"
                value={requestData.ipAddress}
                onChange={handleRequestChange}
                placeholder="192.168.1.50"
              />

              <div className="flex items-end">

                <button
                  type="submit"
                  disabled={analyzing}
                  className="flex h-11 w-full items-center justify-center gap-2 rounded-lg bg-cyan-500 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Shield className="h-4 w-4" />

                  {analyzing
                    ? "Analyzing..."
                    : "Analyze Request"}
                </button>

              </div>

            </div>

            <div className="mt-4">

              <label className="mb-2 block text-xs font-medium text-slate-400">
                Payload
              </label>

              <textarea
                name="payload"
                value={requestData.payload}
                onChange={handleRequestChange}
                rows={4}
                placeholder="Enter request payload to analyze..."
                className="w-full resize-none rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 focus:border-cyan-500"
              />

            </div>

          </form>

          {/* ANALYSIS RESULT */}

          {lastAnalysis && (

            <div className="mt-5 rounded-xl border border-slate-800 bg-slate-950 p-5">

              <div className="mb-4 flex flex-col justify-between gap-3 sm:flex-row sm:items-center">

                <div className="flex items-center gap-3">

                  {lastAnalysis.detected ? (

                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-red-500/10">
                      <AlertTriangle className="h-5 w-5 text-red-400" />
                    </div>

                  ) : (

                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/10">
                      <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                    </div>

                  )}

                  <div>

                    <h4 className="font-semibold">

                      {lastAnalysis.detected
                        ? "Threat Detected"
                        : "Request Appears Safe"}

                    </h4>

                    <p className="text-xs text-slate-500">
                      Analysis completed
                    </p>

                  </div>

                </div>

                <div
                  className={`rounded-lg border px-3 py-2 text-xs font-semibold ${severityClass(
                    lastAnalysis.analysis?.severity ||
                      "LOW"
                  )}`}
                >
                  {lastAnalysis.analysis?.severity ||
                    "LOW"}
                </div>

              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">

                <ResultBox
                  label="Detection"
                  value={
                    lastAnalysis.analysis?.type
                      ? typeLabel(
                          lastAnalysis.analysis.type
                        )
                      : "NONE"
                  }
                />

                <ResultBox
                  label="Risk Score"
                  value={`${lastAnalysis.analysis?.riskScore ?? 0}/100`}
                />

                <ResultBox
                  label="Description"
                  value={
                    lastAnalysis.analysis?.description ||
                    "No known malicious pattern detected"
                  }
                />

              </div>

            </div>

          )}

        </section>

        {/* EVENTS */}

        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60">

          <div className="flex flex-col justify-between gap-3 border-b border-slate-800 p-5 sm:flex-row sm:items-center">

            <div>

              <h3 className="font-semibold">
                Security Events
              </h3>

              <p className="mt-1 text-xs text-slate-500">
                Live threats stored in MongoDB
              </p>

            </div>

            <div className="flex items-center gap-2 text-xs text-slate-500">
              <Database className="h-4 w-4" />
              {events.length} events
            </div>

          </div>

          {loadingEvents ? (

            <div className="flex h-40 items-center justify-center text-sm text-slate-500">
              Loading security events...
            </div>

          ) : events.length === 0 ? (

            <div className="flex h-48 flex-col items-center justify-center text-center">

              <Shield className="mb-3 h-10 w-10 text-slate-700" />

              <p className="text-sm text-slate-500">
                No security events detected.
              </p>

              <p className="mt-1 text-xs text-slate-600">
                Analyze a request to generate an event.
              </p>

            </div>

          ) : (

            <div className="overflow-x-auto">

              <table className="w-full min-w-[850px] text-left">

                <thead>

                  <tr className="border-b border-slate-800 text-xs uppercase tracking-wider text-slate-500">

                    <th className="px-5 py-4">
                      Threat
                    </th>

                    <th className="px-5 py-4">
                      Severity
                    </th>

                    <th className="px-5 py-4">
                      Risk
                    </th>

                    <th className="px-5 py-4">
                      Method
                    </th>

                    <th className="px-5 py-4">
                      Endpoint
                    </th>

                    <th className="px-5 py-4">
                      IP Address
                    </th>

                    <th className="px-5 py-4">
                      Time
                    </th>

                  </tr>

                </thead>

                <tbody>

                  {events.map((event) => (

                    <tr
                      key={event._id || event.id}
                      className="border-b border-slate-800/60 transition hover:bg-slate-800/30"
                    >

                      <td className="px-5 py-4">

                        <div className="flex items-center gap-3">

                          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-red-500/10">
                            <ShieldAlert className="h-4 w-4 text-red-400" />
                          </div>

                          <span className="whitespace-nowrap text-sm font-medium">
                            {typeLabel(event.type)}
                          </span>

                        </div>

                      </td>

                      <td className="px-5 py-4">

                        <span
                          className={`rounded-md border px-2.5 py-1 text-xs font-semibold ${severityClass(
                            event.severity
                          )}`}
                        >
                          {event.severity}
                        </span>

                      </td>

                      <td className="px-5 py-4">

                        <div className="flex items-center gap-2">

                          <div className="h-1.5 w-16 overflow-hidden rounded-full bg-slate-800">

                            <div
                              className="h-full rounded-full bg-cyan-400"
                              style={{
                                width: `${Math.min(
                                  100,
                                  Math.max(
                                    0,
                                    event.riskScore
                                  )
                                )}%`,
                              }}
                            />

                          </div>

                          <span className="text-xs text-slate-400">
                            {event.riskScore}
                          </span>

                        </div>

                      </td>

                      <td className="px-5 py-4">

                        <span className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-300">
                          {event.method}
                        </span>

                      </td>

                      <td className="max-w-[220px] truncate px-5 py-4 text-xs text-slate-400">
                        {event.endpoint}
                      </td>

                      <td className="px-5 py-4 text-xs text-slate-400">
                        {event.ipAddress}
                      </td>

                      <td className="whitespace-nowrap px-5 py-4 text-xs text-slate-500">
                        {formatDate(
                          event.timestamp ||
                            event.createdAt
                        )}
                      </td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          )}

        </section>

        <footer className="py-8 text-center text-xs text-slate-600">
          SentinelAPI • API Threat Detection & Security Monitoring
        </footer>

      </main>

    </div>
  );
}

function StatCard({
  title,
  value,
  icon: Icon,
  description,
  danger = false,
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">

      <div className="flex items-start justify-between">

        <div>

          <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
            {title}
          </p>

          <p
            className={`mt-3 text-3xl font-bold ${
              danger && Number(value) > 0
                ? "text-red-400"
                : "text-slate-100"
            }`}
          >
            {value}
          </p>

        </div>

        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-800">
          <Icon
            className={`h-5 w-5 ${
              danger
                ? "text-red-400"
                : "text-cyan-400"
            }`}
          />
        </div>

      </div>

      <p className="mt-3 text-xs text-slate-600">
        {description}
      </p>

    </div>
  );
}

function StatusRow({ name, status, online }) {
  return (
    <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950/50 px-4 py-3">

      <div className="flex items-center gap-3">
        <Globe className="h-4 w-4 text-slate-500" />

        <span className="text-sm text-slate-300">
          {name}
        </span>
      </div>

      <div className="flex items-center gap-2 text-xs">

        <span
          className={`h-2 w-2 rounded-full ${
            online
              ? "bg-emerald-400"
              : "bg-red-400"
          }`}
        />

        <span
          className={
            online
              ? "text-emerald-400"
              : "text-red-400"
          }
        >
          {status}
        </span>

      </div>

    </div>
  );
}

function InputField({
  label,
  name,
  value,
  onChange,
  placeholder,
}) {
  return (
    <div>

      <label className="mb-2 block text-xs font-medium text-slate-400">
        {label}
      </label>

      <input
        name={name}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        className="h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-4 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 focus:border-cyan-500"
      />

    </div>
  );
}

function ResultBox({ label, value }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">

      <p className="text-xs uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p className="mt-2 break-words text-sm font-medium text-slate-300">
        {value}
      </p>

    </div>
  );
}

function formatDate(timestamp) {
  if (!timestamp) return "Unknown";

  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return date.toLocaleString();
}

export default App;