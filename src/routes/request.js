const express = require("express");
const verifyToken = require("../middlewares/verifyToken");
const ConnectionRequest = require("../models/ConnectionRequest");
const User = require("../models/user");
const router = express.Router();
router.get("/request/send/:status/:touserid", verifyToken, async (req, res) => {
  try {
    const fromUserId = req.user._id;
    const toUserId = req.params.touserid;
    const status = req.params.status;
     const allowedStatus = ["ignored","interested"];
     if(!allowedStatus.includes(status)){
         return res
          .status(400)
          .json({ message: "Invalid status type: " + status });
     }
     const toUser = await User.findById(toUserId);
     if(!toUser){
      return res.status(400).json({
        message:"User not found",
      });
    }
      const existingConnectionRequest = await ConnectionRequest.findOne({
        $or:[
            {fromUserId:fromUserId,toUserId:toUserId},
            {fromUserId:toUserId,toUserId:fromUserId},
        ]
      });
      if(existingConnectionRequest){
        return res.status(400).json({messaage:"Connection Request Already Exists!!"});
      }

     
    const connectionRequest = new ConnectionRequest({
      fromUserId,
      toUserId,
      status,
    });
    const data = await connectionRequest.save();
    res.status(201).json({
      message:
        req.user.firstName +
        " is" +
        status +
        " in " +
        toUser.firstName +
        "'s" +
        "profile",
      data,
      success: true,
    });
  } catch (err) {
    console.log(err);
      res.status(400).send("ERROR: " + err.message);
  }
});
router.post("/request/review/:status/:requestId",verifyToken,async(req,res)=>{
  try{
    const {status,requestId} = req.params;
  const loggendInUser = req.user;
  const allowedStatus = [ "accepted", "rejected"];
  if(!allowedStatus.includes(status)){
    return res.status(400).json({
      message:"status not allowed"
    });
  }
    const existingConnectionRequest = await ConnectionRequest.findOne({
      _id:requestId,
      toUserId:loggendInUser._id,
      status:"interested",

    }).populate("fromUserId", "firstName lastName email");
    if(!existingConnectionRequest){
       return res
          .status(404)
          .json({ message: "Connection request not found" });
    }
    existingConnectionRequest.status = status;
    const data = await existingConnectionRequest.save();
    
res.json({
  success: true,
  message: `You have ${status} the connection request from ${existingConnectionRequest.fromUserId.firstName}`,
  data
});


  }catch(err){
     res.status(400).send("ERROR: " + err.message);
  }
  
  
})
