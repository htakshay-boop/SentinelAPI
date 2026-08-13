const SecurityEvent = require("../models/SecurityEvent");
const { analyzeRequest } = require("../services/threatDetectionService");

const analyzeSecurityRequest = async (req, res) => {
  try {
    const {
      method = "GET",
      endpoint = "/",
      payload = "",
      ipAddress = "127.0.0.1",
    } = req.body;

    const analysis = analyzeRequest({
      method,
      endpoint,
      payload,
      ipAddress,
    });

    let savedEvent = null;

    // Save detected threats to MongoDB
    if (analysis.detected) {
      savedEvent = await SecurityEvent.create({
        type: analysis.type,
        severity: analysis.severity,
        riskScore: analysis.riskScore,
        ipAddress,
        method,
        endpoint,
        payload,
        description: analysis.description,
      });

      // Send the newly detected threat to connected dashboards
      const io = req.app.get("io");

      if (io) {
        io.emit("security-event", {
          id: savedEvent._id,
          type: savedEvent.type,
          severity: savedEvent.severity,
          riskScore: savedEvent.riskScore,
          ipAddress: savedEvent.ipAddress,
          method: savedEvent.method,
          endpoint: savedEvent.endpoint,
          payload: savedEvent.payload,
          description: savedEvent.description,
          timestamp: savedEvent.timestamp,
        });
      }
    }

    res.status(200).json({
      success: true,
      detected: analysis.detected,
      analysis,
      event: savedEvent,
    });
  } catch (error) {
    console.error("Security analysis failed:", error);

    res.status(500).json({
      success: false,
      message: "Security analysis failed",
      error: error.message,
    });
  }
};

const getSecurityEvents = async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 100);

    const events = await SecurityEvent.find()
      .sort({ timestamp: -1 })
      .limit(limit);

    res.json({
      success: true,
      count: events.length,
      events,
    });
  } catch (error) {
    console.error("Fetching security events failed:", error);

    res.status(500).json({
      success: false,
      message: "Failed to fetch security events",
      error: error.message,
    });
  }
};

module.exports = {
  analyzeSecurityRequest,
  getSecurityEvents,
};