// path files : customer-portal/backend/index.js
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const session = require("express-session");
const { ethers } = require("ethers");
const connection = require("./dbConnection");
const authRoutes = require("./authRoutes");
const institutionRoutes = require("./routes/institutionRoutes");
const accountRoutes = require("./routes/accountRoutes");
const userRoutes = require("./routes/userRoutes");
const internalRoutes = require("./routes/internalRoutes");

const app = express();

// Enable CORS for requests from your frontend and allow credentials.
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://localhost:3001",
      "http://localhost:3002",
    ],
    credentials: true,
  })
);

app.use(bodyParser.json());

// Configure session middleware
app.use(
  session({
    secret:
      "2c926d469d275c022250b4adb340bb36bbfcca8f58ce6e6d868bd57f480b4eabf3d3c4cd622e945df21b263a61e39c65b9890c60e9aa397318407b7d35f9a764", // Use an environment variable in production
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set true if using HTTPS
      httpOnly: true,
    },
  })
);

app.use("/auth", authRoutes);

app.use("/institutions", institutionRoutes);

app.use("/account", accountRoutes);

app.use("/user", userRoutes);

app.use("/internal", internalRoutes);

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`Express server running on port ${PORT}`);
});
