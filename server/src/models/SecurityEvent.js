const mongoose = require("mongoose");

const securityEventSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      required: true,
      enum: [
        "SQL_INJECTION",
        "XSS",
        "BRUTE_FORCE",
        "PATH_TRAVERSAL",
        "COMMAND_INJECTION",
        "SUSPICIOUS_REQUEST",
      ],
    },

    severity: {
      type: String,
      required: true,
      enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    },

    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },

    ipAddress: {
      type: String,
      required: true,
    },

    method: {
      type: String,
      required: true,
    },

    endpoint: {
      type: String,
      required: true,
    },

    payload: {
      type: String,
      default: "",
    },

    description: {
      type: String,
      required: true,
    },

    timestamp: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("SecurityEvent", securityEventSchema);