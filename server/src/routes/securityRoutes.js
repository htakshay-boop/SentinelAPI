const express = require("express");

const {
  analyzeSecurityRequest,
  getSecurityEvents,
} = require("../controllers/securityController");

const router = express.Router();

router.post("/analyze", analyzeSecurityRequest);

router.get("/events", getSecurityEvents);

module.exports = router;