const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const User = require("../models/user");

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      console.log(profile);
      try {
        let user = await User.findOne({ email: profile.emails[0].value });
        console.log("google user ", user);
        if (!user) {
          user = await User.create({
            firstName: profile.name.givenName || "Google",
            lastName: profile.name.familyName || "User",
            email: profile.emails[0].value,
            password: "GOOGLE_AUTH_NO_PASSWORD",
            profileImg: profile.photos[0]?.value,
            emailVerified: true,
          });
        }

        done(null, user);
      } catch (error) {
        done(error, null);
      }
    }
  )
);
