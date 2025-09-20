const express = require("express");
const router = express.Router();
const verifyToken = require("../middlewares/verifyToken");
const ConnectionRequest = require("../models/ConnectionRequest");
const User = require("../models/user");
const USER_SAFE_DATA = "firstName lastName profileImg age gender about skills";
//pendingConnection
router.get("/pendingConnection", verifyToken, async (req, res) => {
  try {
    const loggedInUser = req.user;
    const existingConnectionReq = await ConnectionRequest.find({
      toUserId: loggedInUser._id,
      status: "interested",
    }).populate(fromUserId, USER_SAFE_DATA);

    res
      .status(200)
      .json({ message: " Pending Request Data fetched successfully",data:existingConnectionReq });
  } catch (err) {
    req.statusCode(400).send("ERROR: " + err.message);
  }
});
//get all connection
router.get("/allConnection", verifyToken, async (req, res) => {
  try {
    const loggedInUser = req.user;
    const AllConnection = await ConnectionRequest.find({
      $or: [
        { fromUserId: loggedInUser._id, status: "accepted" },
        { toUserId: loggedInUser._id, status: "accepted" },
      ],
    })
      .populate("fromUserId", USER_SAFE_DATA)
      .populate("toUserId", USER_SAFE_DATA);
    const data = AllConnection.map((item) => {
      if (item.fromUserId._id.toString() === loggedInUser._id.toString()) {
        return item.toUserId;
      } else {
        return item.fromUserId;
      }
    });
    res
      .status(200)
      .json({
        message: "All Connection Data Fetch Successfully",
        data: AllConnection,
      });
  } catch (err) {
    res.status(400).send({ message: err.message });
  }
});
//feed api and pagination
router.get("/feed", verifyToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page)|| 1;
    const limit = parseInt(req.query.limit)|| 10;
    limit = limit > 50 ? 50:limit;
    const skip = (page-1)*limit;
    const loggedInUser = req.user;
    const totalConnection = await ConnectionRequest.find({
      $or: [
        {
          fromUserId: loggedInUser._id,
        },
        { toUserId: loggedInUser._id },
      ],
    }).select("fromUserId toUserId");
    const hideUserDataFromFeed = new Set();
    const data =  totalConnection.forEach((item)=>{
        hideUserDataFromFeed.add(item.fromUserId.toString());
        hideUserDataFromFeed.add(item.toUserId.toString());
    });
    
     const user = await User.find({
        $and:[
            {_id:{$nin:Array.from(hideUserDataFromFeed)}},
            {_id:{$ne:loggedInUser._id}}
        ]

     }).select(USER_SAFE_DATA).skip(skip).limit(limit);
     res.status(200).json({message:"Feed data Fetch Successfully",data:user})




  } catch (err) {
    res.status(400).send({ message: err.message });
  }
});

module.exports = router;
