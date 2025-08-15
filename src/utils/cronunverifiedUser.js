const cron = require("node-cron");
const User = require("../models/user");

const cronUnverifiedUser = () => {
  cron.schedule("0 * * * *", async () => {
    try {
      const result = await User.deleteMany({
        emailVerified: false,
        createdAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) },
      });
      // console.log("Deleted unverified users:", result.deletedCount);
    } catch (err) {
      console.error("Error deleting unverified users:", err);
    }
  });
};

module.exports = cronUnverifiedUser;
