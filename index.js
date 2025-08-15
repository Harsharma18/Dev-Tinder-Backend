require("dotenv").config();
const express = require("express");
const app = express();
const cookieParser = require("cookie-parser");
const cors = require("cors");
app.use(express.json());
app.use(cookieParser());
app.use(cors());

const User = require("./src/models/user");
const authRouter = require("./src/routes/auth");
app.use("/api/v1/auth", authRouter);
const redisClient = require("./src/config/redis");
const connectDb = require("./src/config/database");
const PORT = process.env.PORT || 5000;
let redisConnected = false;

redisClient.on("error", (err) => {
  if (!redisConnected) {
    console.error("❌ Redis Client Error:", err.message);
    redisConnected = true;
  }
}); 

const passport = require("passport");
const cronUnverifiedUser = require("./src/utils/cronunverifiedUser");
app.use(passport.initialize());
require("./src/config/passport");

const initializeConnection = async () => {
  try {
    // await redisClient.connect();
    // console.log("Redis connected");

    // await connectDb();
    // console.log("MongoDB connected");
    await Promise.all([redisClient.connect(), connectDb()]);
    console.log("Redis and MongoDB connected");
      cronUnverifiedUser();
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Failed to initialize:", error);
  }
};

initializeConnection();
