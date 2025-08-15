// models/User.js
const mongoose = require("mongoose");
const validator = require("validator");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const userSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: true,
      minLength: 4,
      maxLength: 20,
    },
    lastName: {
      type: String,
    },
    email: {
      type: String,
      lowercase: true,
      required: true,
      unique: true,
      trim: true,
      validate(value) {
        if (!validator.isEmail(value)) {
          throw new Error("Invalid email address: " + value);
        }
      },
    },
    password: {
      type: String,
      required: true,
    },
    emailVerified: {
      type: Boolean,
      default: false,
    },
    verificationEmailToken: { type: String },
    verificationEmailTokenExpires: { type: Date },
    otp: {
      type: String,
    },
    otpExpiry: {
      type: Date,
    },
    otpVerified: {
      type: Boolean,
      default: false,
    },

    age: {
      type: Number,
      min: 18,
    },
    gender: {
      type: String,
      enum: {
        values: ["male", "female", "other"],
        message: `{VALUE} is not a valid gender type`,
      },
      // validate(value) {
      //   if (!["male", "female", "others"].includes(value)) {
      //     throw new Error("Gender data is not valid");
      //   }
      // },
    },
    about: {
      type: String,
      default: "This is a default about of the user!",
    },
    skills: {
      type: [String],
    },
    profileImg: {
      type: String,
      default: "https://geographyandyou.com/images/user-profile.png",
    },
  },
  {
    timestamps: true,
  }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});
userSchema.methods.comparepassword = async function (candidatepassword) {
  const password = await bcrypt.compare(candidatepassword, this.password);
  return password;
};
// Generate & set email verification token
userSchema.methods.createVerificationToken = function () {
  if (
    this.verificationEmailTokenExpires &&
    this.verificationEmailTokenExpires > Date.now()
  ) {
    throw new Error("Please wait before requesting another verification email");
  }
  const token = crypto.randomBytes(32).toString("hex");
  this.verificationEmailToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
  this.verificationEmailTokenExpires = Date.now() + 10 * 60 * 1000; // 10 mins
  return token;
};
const User = mongoose.model("User", userSchema);
module.exports = User;
