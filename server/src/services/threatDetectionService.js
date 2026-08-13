const requestTracker = new Map();

const detectionPatterns = [
  {
    type: "SQL_INJECTION",
    severity: "CRITICAL",
    baseScore: 90,
    patterns: [
      /('|%27)\s*(or|and)\s+/i,
      /\bunion\s+(all\s+)?select\b/i,
      /\bselect\s+.+\s+from\b/i,
      /\bdrop\s+table\b/i,
      /\binsert\s+into\b/i,
      /\bdelete\s+from\b/i,
      /\bupdate\s+.+\s+set\b/i,
      /--/,
      /\/\*/,
      /\bexec\s*\(/i,
    ],
    description: "Possible SQL injection payload detected",
  },

  {
    type: "XSS",
    severity: "HIGH",
    baseScore: 80,
    patterns: [
      /<script\b[^>]*>/i,
      /javascript\s*:/i,
      /onerror\s*=/i,
      /onload\s*=/i,
      /<iframe\b/i,
      /<img\b[^>]+onerror/i,
      /document\.cookie/i,
    ],
    description: "Possible cross-site scripting payload detected",
  },

  {
    type: "PATH_TRAVERSAL",
    severity: "HIGH",
    baseScore: 75,
    patterns: [
      /\.\.\//,
      /\.\.\\/,
      /%2e%2e%2f/i,
      /%2e%2e%5c/i,
      /\.\.%2f/i,
    ],
    description: "Possible path traversal attempt detected",
  },

  {
    type: "COMMAND_INJECTION",
    severity: "CRITICAL",
    baseScore: 95,
    patterns: [
      /;\s*(cat|ls|pwd|whoami|id)\b/i,
      /\|\s*(cat|ls|pwd|whoami|id)\b/i,
      /&&\s*(cat|ls|pwd|whoami|id)\b/i,
      /\$\([^)]*\)/,
      /`[^`]+`/,
    ],
    description: "Possible command injection payload detected",
  },
];

const calculateSeverity = (score) => {
  if (score >= 90) return "CRITICAL";
  if (score >= 61) return "HIGH";
  if (score >= 31) return "MEDIUM";
  return "LOW";
};

const checkBruteForce = (ipAddress, endpoint) => {
  const key = `${ipAddress}:${endpoint}`;
  const now = Date.now();
  const windowMs = 60 * 1000;

  let requests = requestTracker.get(key) || [];

  requests = requests.filter(
    (timestamp) => now - timestamp < windowMs
  );

  requests.push(now);

  requestTracker.set(key, requests);

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

const analyzeRequest = ({
  method,
  endpoint,
  payload = "",
  ipAddress,
}) => {
  const combinedInput = `${method} ${endpoint} ${payload}`;

  const detections = [];

  // Pattern-based detection
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

  // Rate-based brute-force detection
  const bruteForce = checkBruteForce(
    ipAddress,
    endpoint
  );

  if (bruteForce) {
    detections.push(bruteForce);
  }

  // No threat
  if (detections.length === 0) {
    return {
      detected: false,
      riskScore: 5,
      severity: "LOW",
      type: "SUSPICIOUS_REQUEST",
      description: "No known malicious pattern detected",
      method,
      endpoint,
      payload,
      ipAddress,
    };
  }

  const highestRisk = Math.min(
    100,
    Math.max(
      ...detections.map(
        (detection) => detection.riskScore
      )
    ) +
      (detections.length - 1) * 5
  );

  const primaryDetection = detections.reduce(
    (highest, current) =>
      current.riskScore > highest.riskScore
        ? current
        : highest
  );

  return {
    detected: true,
    type: primaryDetection.type,
    severity: calculateSeverity(highestRisk),
    riskScore: highestRisk,
    description: primaryDetection.description,
    method,
    endpoint,
    payload,
    ipAddress,
    detections,
  };
};

module.exports = {
  analyzeRequest,
};