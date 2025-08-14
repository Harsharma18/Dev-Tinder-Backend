//Sliding window
const redisClient = require("../config/redis");
const rateLimiter = ({ keyPrefix, maxRequest, windowseconds }) => {
  return async (req, res, next) => {
    try {
      const ip = req.ip;
      const key = `${keyPrefix}:${ip}`;
      const currentTime = Date.now();
      const windowstartTime = currentTime - windowseconds * 1000;
      //old data remove which is outside from windostartTime
      await redisClient.zRemRangeByScore(key, 0, windowstartTime);
      //check howmany request is current in sliding window
      const numberOfRequest = await redisClient.zCard(key);
      console.log(
        `${key} → ${numberOfRequest} requests in current sliding window`
      );
      //or await redisClient.zCount(key,currentTIme,currentTIme);//key ,min,max valu it use z card only use key it automaticaly sort
      if (numberOfRequest >= maxRequest) {
        return res.status(429).json({
          success: false,
          message: `${keyPrefix} route has too many requests. Cooldown `,
        });
      }
      //add current request score is timestamp sorted
      await redisClient.zAdd(key, [
        { score: currentTime, value: `${currentTime}-${Math.random()}` },
      ]);
      await redisClient.expire(key, windowseconds);

      next();
    } catch (err) {
      console.error("Sliding window error:", err);
      res.status(500).json({ success: false, message: "Server Error" });
    }
  };
};
module.exports = rateLimiter;

//Fixed WIndow
// const redisClient = require("../config/redis");

// const rateLimiter = ({ keyPrefix, maxRequest, windowseconds }) => {
//   return async (req, res, next) => {
//     try {
//       const ip = req.ip;
//       const key = `${keyPrefix}:${ip}`;

//       const numberOfRequest = await redisClient.incr(key);

//       if (numberOfRequest === 1) {
//         await redisClient.expire(key, windowseconds);
//       }

//       console.log(`${key} → ${numberOfRequest} requests`);

//       if (numberOfRequest >= maxRequest) {
//         return res.status(429).json({
//           success: false,
//           message: `${keyPrefix} route has too many requests from this IP. Cooldown: ${windowseconds} seconds.`,
//         });
//       }

//       next();
//     } catch (err) {
//       console.error("Rate limiter error:", err);
//       res.status(500).json({ success: false, message: "Server Error" });
//     }
//   };
// };

// module.exports = rateLimiter;

// const redisClient = require("../config/redis");
// const User = require("../models/user");
// const rateLimiter = async(req,res,next)=>{
//     try{
//          const ip = req.ip;
//     console.log(ip);
//     const numberOfRequest  = await redisClient.incr(ip);
//     console.log("count request by ip address", numberOfRequest);
//     if(numberOfRequest>=60){
//         throw new Error("User Limit excedded");
//     }
//     if(numberOfRequest===1){
//         await redisClient.expire(3600);
//     }
//    next();
//     }catch(err){
//         console.log(err);
//         res.status(500).json({message: "Server Error"},err);
//     }

// }
// module.exports = rateLimiter;
