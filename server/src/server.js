const securityRoutes = require("./routes/securityRoutes");
const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
require("dotenv").config();
const connectDatabase = require("./config/database");

const app = express();

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173",
    methods: ["GET", "POST"]
  }
});

app.set("io", io);

app.use(cors());
app.use(express.json());

app.use("/api/security", securityRoutes);

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "SentinelAPI backend is running",
    timestamp: new Date().toISOString()
  });
});

io.on("connection", (socket) => {
  console.log(`Dashboard connected: ${socket.id}`);

  socket.on("disconnect", () => {
    console.log(`Dashboard disconnected: ${socket.id}`);
  });
});
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  await connectDatabase();

  server.listen(PORT, () => {
    console.log(`SentinelAPI server running on port ${PORT}`);
  });
};

startServer();