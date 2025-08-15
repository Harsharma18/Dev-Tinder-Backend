const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const User = require("../models/user");
const { validateSignUpdata } = require("../utils/validation");
const validator = require("validator");
const verifyToken = require("../middlewares/verifyToken");
const redisClient = require("../config/redis");
const passport = require("passport");
const sendMail = require("../utils/Emails");
const rateLimiter = require("../middlewares/ratelimiter");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
//  REGISTER
router.post(
  "/register",
  rateLimiter({ keyPrefix: "register", maxRequest: 5, windowseconds: 60 }),
  async (req, res) => {
    try {
      validateSignUpdata(req);

      const { firstName, lastName, email, password } = req.body;

      let existingUser = await User.findOne({ email });
      if (existingUser && existingUser.emailVerified) {
        return res
          .status(409)
          .json({ success: false, message: "Email already registered" });
      }

      if (!existingUser) {
        existingUser = new User({ firstName, lastName, email, password });
      } else {
        // exists but not verified -> update fields and issue new token
        existingUser.firstName = firstName;
        existingUser.lastName = lastName;
        existingUser.password = password;
      }
      const token = existingUser.createVerificationToken();

      const newUser = await existingUser.save();
      console.log("register", newUser);

      const link = `http://localhost:7777/api/v1/auth/verifyEmail/${token}`;
      try {
        await sendMail(
          existingUser.email,
          "Verify Your Email - Dev Tinder",
          `
          <div style="font-family: Arial, sans-serif; text-align: center;">
            <h2>Welcome to Dev Tinder</h2>
            <p>Hi <b>${existingUser.firstName}</b>, please verify your email to activate your account.</p>
            <a href="${link}" style="background: #011d12; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px;">
              Verify Email
            </a>
          </div>
        `
        );
      } catch (err) {
        await User.deleteOne({ _id: existingUser._id });
        return res.status(400).json({
          success: false,
          message: "Invalid or undeliverable email. Please use a real email.",
        });
      }

      res.status(200).json({
        success: true,
        message: "Please check your email to verify your account.",
      });
    } catch (err) {
      console.log(err);
      res.status(400).json({ success: false, message: err.message });
    }
  }
);

router.get("/verifyEmail/:token", async (req, res) => {
  try {
    const { token } = req.params;
    if (!token)
      return res.status(400).json({ message: "Verification token required" });
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    const newUser = await User.findOne({
      verificationEmailToken: hashedToken,
      verificationEmailTokenExpires: { $gt: Date.now() },
    });
    if (!newUser) {
      return res.status(400).json({
        message:
          "Invalid or expired verification link. Request a new verification link",
      });
    }
    if (newUser.emailVerified) {
      newUser.verificationEmailToken = undefined;
      newUser.verificationEmailTokenExpires = undefined;
      await newUser.save();
      return res
        .status(200)
        .json({ message: "Email is already verified. You can login." });
    }

    newUser.emailVerified = true;
    newUser.verificationEmailToken = undefined;
    newUser.verificationEmailTokenExpires = undefined;
    await newUser.save();

    return res
      .status(200)
      .json({ message: "Email verified successfully. You can now login." });
  } catch (err) {
    console.error("Verify error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});
/* RESEND VERIFICATION link */
router.post(
  "/resend-verification",
  rateLimiter({
    keyPrefix: "resend-verification",
    maxRequest: 3,
    windowseconds: 300,
  }),
  async (req, res) => {
    try {
      const { email } = req.body;

      if (!email || !validator.isEmail(email)) {
        return res.status(400).json({ message: "Valid email is required" });
      }
      const user = await User.findOne({ email });
      if (!user)
        return res
          .status(404)
          .json({ message: "No account found with this email" });
      if (user.emailVerified)
        return res.status(400).json({ message: "Email is already verified" });

      const token = user.createVerificationToken();
      const link = `http://localhost:7777/api/v1/auth/verifyEmail/${token}`;

      await user.save();

      try {
        await sendMail(
          user.email,
          "Verify Your Email - Dev Tinder",
          `
          <div style="font-family: Arial, sans-serif; text-align: center;">
            <h2>Welcome to Dev Tinder</h2>
            <p>Hi <b>${user.firstName}</b>, please verify your email to activate your account.</p>
            <a href="${link}" style="background: #011d12; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px;">
              Verify Email
            </a>
          </div>
        `
        );
      } catch (err) {
        return res.status(400).json({
          message: "Invalid or undeliverable email. Please use a real email.",
        });
      }

      return res.status(200).json({
        message: "Verification email resent. Please check your inbox.",
      });
    } catch (err) {
      console.error("Resend verification error:", err);
      return res.status(500).json({ message: "Server error" });
    }
  }
);
//forgot password
router.post(
  "/forgot-password",
  rateLimiter({ keyPrefix: "forgot", maxRequest: 3, windowseconds: 300 }),
  async (req, res) => {
    try {
      const { email } = req.body;
      if (!validator.isEmail(email)) {
        return res
          .status(400)
          .json({ success: false, message: "Invalid email" });
      }
      const user = await User.findOne({ email });
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }
      // Generate a random 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const hashotp = await bcrypt.hash(otp, 10);

      if (user.otp && Date.now() < user.otpExpiry.getTime()) {
        return res.status(400).json({
          message: "OTP already sent and still valid. Please wait.",
        });
      }
      // Set OTP expiry to 5 minute from now
      const expiry = new Date(Date.now() + 5 * 60 * 1000);
      user.otp = hashotp;
      user.otpExpiry = expiry;
      await user.save();
      try {
        await sendMail(
          user.email,
          "Your Password Reset OTP - Dev Tinder",
          `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px; background-color: #f9f9f9; text-align: center;">
      <h2 style="color: #011d12;">Password Reset Request</h2>
      <p>Hi <b>${user.firstName}</b>,</p>
      <p>You requested to reset your password. Use the OTP below to reset it. This OTP will expire in <b>5 minutes</b>.</p>
      <div style="margin: 20px 0; padding: 15px; background-color: #011d12; color: white; font-size: 24px; font-weight: bold; border-radius: 5px; display: inline-block;">
        ${otp}
      </div>
      <p style="font-size: 12px; color: #555;">If you did not request a password reset, please ignore this email.</p>
    </div>
    `
        );
      } catch (err) {
        return res.status(400).json({
          success: false,
          message: "Invalid or undeliverable email. Please use a real email.",
        });
      }

      res.status(200).json({
        success: true,
        message: "OTP sent to your email",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);
router.post(
  "/resend-otp",
  rateLimiter({ keyPrefix: "resend-otp", maxRequest: 2, windowseconds: 300 }),
  async (req, res) => {
    try {
      const { email } = req.body;
      if (!validator.isEmail(email)) {
        return res
          .status(400)
          .json({ success: false, message: "Invalid email" });
      }
      const user = await User.findOne({ email });
      console.log("user.otpexpiry", user.otpExpiry);
      console.log("expire otp time", user.otpExpiry.getTime());
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }
      if (user.otp && Date.now() < user.otpExpiry.getTime()) {
        return res.status(400).json({
          message: "Otp Already sent and still valid",
        });
      }

      // New OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const hashotp = await bcrypt.hash(otp, 10);
      const expiry = new Date(Date.now() + 5 * 60 * 1000);
      user.otp = hashotp;
      user.otpExpiry = expiry;
      await user.save();
      try {
        await sendMail(
          user.email,
          "Your New OTP - Dev Tinder",
          `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px; background-color: #f1f8f7; text-align: center;">
      <h2 style="color: #011d12;">Your New OTP</h2>
      <p>Hi <b>${user.firstName}</b>,</p>
      <p>You requested a new OTP for password reset. Use the OTP below. It will expire in <b>5 minutes</b>.</p>
      <div style="margin: 20px 0; padding: 15px; background-color: #011d12; color: white; font-size: 24px; font-weight: bold; border-radius: 5px; display: inline-block;">
        ${otp}
      </div>
      <p style="font-size: 12px; color: #555;">If you did not request this, please ignore this email.</p>
    </div>
    `
        );
      } catch (err) {
        return res.status(400).json({
          success: false,
          message: "Invalid or undeliverable email. Please use a real email.",
        });
      }

      res.status(200).json({
        success: true,
        message: "New OTP sent to your email",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);
router.post(
  "/verify-otp",
  rateLimiter({ keyPrefix: "verify-otp", maxRequest: 5, windowseconds: 900 }),
  async (req, res) => {
    try {
      const { email, otp } = req.body;
      if (!validator.isEmail(email)) {
        return res
          .status(400)
          .json({ success: false, message: "Invalid email" });
      }
      const user = await User.findOne({ email });
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }
      if (!user.otp || !user.otpExpiry) {
        return res
          .status(400)
          .json({ success: false, message: "No OTP found" });
      }
      if (Date.now() > user.otpExpiry.getTime()) {
        return res.status(400).json({ success: false, message: "OTP expired" });
      }

      const isMatchotp = await bcrypt.compare(otp, user.otp);

      const attemptsKey = `otp_attempts:${email}:${req.ip}`;
      let attempts = parseInt(await redisClient.get(attemptsKey)) || 0;

      if (attempts >= 5) {
        return res
          .status(429)
          .json({ message: "Too many wrong OTP attempts. Try later." });
      }

      if (!isMatchotp) {
        await redisClient.incr(attemptsKey);
        await redisClient.expire(attemptsKey, 15 * 60);
        return res.status(400).json({ message: "Invalid OTP" });
      }
      await redisClient.del(attemptsKey);
      user.otpVerified = true;
      user.otp = undefined;
      user.otpExpiry = undefined;
      await user.save();

      res.status(200).json({
        success: true,
        message: "OTP verified successfully. You can now reset your password.",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);
router.post("/reset-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    if (!validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: "Invalid email" });
    }
    if (
      !validator.isStrongPassword(newPassword, {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
      })
    ) {
      throw new Error(
        "Password must be at least 8 characters and include uppercase, lowercase, number, and symbol."
      );
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    if (!user.otpVerified) {
      return res.status(403).json({ message: "OTP not verified" });
    }

    user.password = newPassword;

    user.otpVerified = false;
    await user.save();
    res.status(200).json({
      success: true,
      message: "Password reset successfully",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
//  LOGIN
router.post(
  "/login",
  rateLimiter({ keyPrefix: "login", maxRequest: 10, windowseconds: 600 }),
  async (req, res) => {
    try {
      const { email, password } = req.body;
      if (!validator.isEmail(email)) {
        throw new Error("Invalid Email");
      }
      const existingUser = await User.findOne({ email });
      if (!existingUser) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }
      if (!existingUser.emailVerified) {
        return res.status(401).json({
          success: false,
          message: "Please verify your email before logging in",
        });
      }

      const isMatch = await existingUser.comparepassword(password);
      if (!isMatch) {
        return res
          .status(401)
          .json({ success: false, message: "Invalid credentials" });
      }

      const token = jwt.sign(
        { id: existingUser._id },
        process.env.JWT_SECRET_KEY,
        { expiresIn: process.env.JWT_EXPIRY || "1d" }
      );

      res.cookie("tokenname", token, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 24 * 60 * 60 * 1000,
      });

      res.status(200).json({
        success: true,
        message: "Login successful",
        user: {
          id: existingUser._id,
          name: existingUser.firstName,
          email: existingUser.email,
        },
        token,
      });
    } catch (err) {
      console.error("Login error:", err);
      res
        .status(500)
        .json({ success: false, message: "Internal Server Error" });
    }
  }
);

// LOGOUT
router.get("/logout", verifyToken, async (req, res) => {
  try {
    const token = req.cookies.tokenname;
    console.log("logout token", token);
    const payload = jwt.decode(token);
    console.log("logout payload", payload);
    await redisClient.set(`token:${token}`, "blocked");
    await redisClient.expireAt(`token:${token}`, payload.exp);
    res.clearCookie("tokenname", {
      httpOnly: true,
      secure: true,
      sameSite: "None",
    });
    res.status(200).json({ success: true, message: "Logout successful" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Logout failed" });
  }
});
router.get("/profiles", verifyToken, async (req, res) => {
  try {
    console.log("Authenticated user:", req.user);
    res
      .status(200)
      .json({ success: true, message: "Access granted", user: req.user });
  } catch (err) {
    console.log(err);
    res.status(401).json({ success: false, message: "Unauthorized" });
  }
});
router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

//  Google OAuth callback

router.get(
  "/google/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect: "/login",
  }),
  async (req, res) => {
    const user = req.user;
    console.log("✅ User from Google Callback:", user);
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, {
      expiresIn: process.env.JWT_EXPIRY || "1d",
    });

    res.cookie("tokenname", token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    });

    // ✅ Respond properly
    res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.firstName,
        email: user.email,
      },
    });
  }
);

module.exports = router;
