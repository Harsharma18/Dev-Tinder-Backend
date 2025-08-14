const jwt = require("jsonwebtoken");
const redisClient = require("../config/redis");
const verifyToken = async (req, res, next) => {
  const token = req.cookies.tokenname;
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    const isBlocked = await redisClient.exists(`token:${token}`);
    if (isBlocked) { 
      throw new Error("invalid Token");
    }
    req.user = decoded;
    console.log(decoded);
    next();
  } catch (err) {
    console.error("Token verification failed:", err.message);
    return res
      .status(403)
      .json({ success: false, message: "Invalid or expired token" });
  }
};
module.exports = verifyToken;
