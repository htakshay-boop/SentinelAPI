const requestTracker = new Map();

/*
 * SentinelAPI Threat Detection Engine
 *
 * Detects:
 * 1. SQL Injection
 * 2. Cross-Site Scripting (XSS)
 * 3. Path Traversal
 * 4. Command Injection
 * 5. Brute Force / Repeated Requests
 */

// ============================================================
// DETECTION RULES
// ============================================================

const detectionPatterns = [
  {
    type: "SQL_INJECTION",
    severity: "CRITICAL",
    baseScore: 90,

    patterns: [
      // OR/AND authentication bypass
      /\b(or|and)\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?/i,

      // Exact common test: OR 1=1
      /\b(or|and)\b\s+1\s*=\s*1\b/i,

      // UNION attacks
      /\bunion\s+(all\s+)?select\b/i,

      // SELECT ... FROM
      /\bselect\s+.+\s+from\b/i,

      // Database modification
      /\bdrop\s+table\b/i,
      /\binsert\s+into\b/i,
      /\bdelete\s+from\b/i,
      /\bupdate\s+.+\s+set\b/i,

      // SQL comments
      /--/,
      /\/\*/,

      // Stored procedure / command execution
      /\bexec\s*\(/i,
    ],

    description: "Possible SQL injection payload detected",
  },

  // ==========================================================
  // XSS
  // ==========================================================

  {
    type: "XSS",
    severity: "HIGH",
    baseScore: 80,

    patterns: [
      /<script\b[^>]*>/i,
      /javascript\s*:/i,
      /onerror\s*=/i,
      /onload\s*=/i,
      /onclick\s*=/i,
      /onmouseover\s*=/i,
      /<iframe\b/i,
      /<img\b[^>]+onerror/i,
      /document\.cookie/i,
      /window\.location/i,
    ],

    description: "Possible cross-site scripting payload detected",
  },

  // ==========================================================
  // PATH TRAVERSAL
  // ==========================================================

  {
    type: "PATH_TRAVERSAL",
    severity: "HIGH",
    baseScore: 75,

    patterns: [
      /\.\.\//,
      /\.\.\\/,

      // Encoded ../
      /%2e%2e%2f/i,
      /%2e%2e%5c/i,
      /\.\.%2f/i,
      /\.\.%5c/i,

      // Double encoded traversal
      /%252e%252e%252f/i,
      /%252e%252e%255c/i,
    ],

    description: "Possible path traversal attempt detected",
  },

  // ==========================================================
  // COMMAND INJECTION
  // ==========================================================

  {
    type: "COMMAND_INJECTION",
    severity: "CRITICAL",
    baseScore: 95,

    patterns: [
      /;\s*(cat|ls|pwd|whoami|id)\b/i,
      /\|\s*(cat|ls|pwd|whoami|id)\b/i,
      /&&\s*(cat|ls|pwd|whoami|id)\b/i,

      // Command substitution
      /\$\([^)]*\)/,

      // Backtick command execution
      /`[^`]+`/,
    ],

    description: "Possible command injection payload detected",
  },
];

// ============================================================
// SEVERITY CALCULATOR
// ============================================================

const calculateSeverity = (score) => {
  if (score >= 90) return "CRITICAL";
  if (score >= 61) return "HIGH";
  if (score >= 31) return "MEDIUM";

  return "LOW";
};

// ============================================================
// INPUT NORMALIZATION
// ============================================================

const normalizeInput = (value) => {
  if (value === undefined || value === null) {
    return "";
  }

  return String(value)
    .replace(/\+/g, " ")
    .trim();
};

// ============================================================
// DECODE URL ENCODED INPUT
// ============================================================

const safelyDecode = (value) => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

// ============================================================
// BRUTE FORCE DETECTION
// ============================================================

const checkBruteForce = (ipAddress, endpoint) => {
  const safeIp = normalizeInput(ipAddress);
  const safeEndpoint = normalizeInput(endpoint);

  const key = `${safeIp}:${safeEndpoint}`;

  const now = Date.now();

  // 60-second detection window
  const windowMs = 60 * 1000;

  let requests = requestTracker.get(key) || [];

  // Remove requests older than 60 seconds
  requests = requests.filter(
    (timestamp) => now - timestamp < windowMs
  );

  // Add current request
  requests.push(now);

  requestTracker.set(key, requests);

  // Five or more requests within 60 seconds
  if (requests.length >= 5) {
    return {
      type: "BRUTE_FORCE",
      severity: "HIGH",
      riskScore: 85,
      description:
        "Possible brute force attack detected from repeated requests",
      matchedPatterns: requests.length,
    };
  }

  return null;
};

// ============================================================
// MAIN ANALYSIS FUNCTION
// ============================================================

const analyzeRequest = ({
  method = "GET",
  endpoint = "",
  payload = "",
  ipAddress = "unknown",
}) => {
  const safeMethod = normalizeInput(method).toUpperCase();
  const safeEndpoint = normalizeInput(endpoint);
  const safePayload = normalizeInput(payload);
  const safeIpAddress = normalizeInput(ipAddress);

  /*
   * Analyze both original and URL-decoded input.
   *
   * Example:
   *
   * %27%20OR%201%3D1
   *
   * becomes:
   *
   * ' OR 1=1
   */

  const decodedEndpoint = safelyDecode(safeEndpoint);
  const decodedPayload = safelyDecode(safePayload);

  const combinedInput = [
    safeMethod,
    safeEndpoint,
    decodedEndpoint,
    safePayload,
    decodedPayload,
  ].join(" ");

  const detections = [];

  // ==========================================================
  // PATTERN BASED DETECTION
  // ==========================================================

  for (const rule of detectionPatterns) {
    const matchedPatterns = rule.patterns.filter((pattern) =>
      pattern.test(combinedInput)
    );

    if (matchedPatterns.length > 0) {
      detections.push({
        type: rule.type,
        severity: rule.severity,
        riskScore: rule.baseScore,
        description: rule.description,
        matchedPatterns: matchedPatterns.length,
      });
    }
  }

  // ==========================================================
  // BRUTE FORCE DETECTION
  // ==========================================================

  const bruteForce = checkBruteForce(
    safeIpAddress,
    safeEndpoint
  );

  if (bruteForce) {
    detections.push(bruteForce);
  }

  // ==========================================================
  // NO THREAT DETECTED
  // ==========================================================

  if (detections.length === 0) {
    return {
      detected: false,
      riskScore: 5,
      severity: "LOW",
      type: "SUSPICIOUS_REQUEST",
      description: "No known malicious pattern detected",

      method: safeMethod,
      endpoint: safeEndpoint,
      payload: safePayload,
      ipAddress: safeIpAddress,

      detections: [],
    };
  }

  // ==========================================================
  // CALCULATE FINAL RISK
  // ==========================================================

  const highestIndividualRisk = Math.max(
    ...detections.map(
      (detection) => detection.riskScore
    )
  );

  /*
   * Add 5 points when multiple attack types
   * are detected in the same request.
   */

  const combinedRisk =
    highestIndividualRisk +
    (detections.length - 1) * 5;

  const highestRisk = Math.min(
    100,
    combinedRisk
  );

  // ==========================================================
  // FIND PRIMARY DETECTION
  // ==========================================================

  const primaryDetection = detections.reduce(
    (highest, current) =>
      current.riskScore > highest.riskScore
        ? current
        : highest
  );

  // ==========================================================
  // FINAL RESULT
  // ==========================================================

  return {
    detected: true,

    type: primaryDetection.type,

    severity: calculateSeverity(
      highestRisk
    ),

    riskScore: highestRisk,

    description:
      primaryDetection.description,

    method: safeMethod,

    endpoint: safeEndpoint,

    payload: safePayload,

    ipAddress: safeIpAddress,

    detections,
  };
};

// ============================================================
// EXPORT
// ============================================================

module.exports = {
  analyzeRequest,
};