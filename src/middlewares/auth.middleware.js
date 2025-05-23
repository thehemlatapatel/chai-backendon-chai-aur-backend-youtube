import { ApiError } from "../utils/ApiError";
import { asyncHandler } from "../utils/asyncHandler";
import jwt from "jsonwebtoken"
import { User } from "../models/user.model";

export const verifyJWt = asyncHandler(async(req,_,next)=>{
try {
     const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer","")
    
     if(!token){
        throw new ApiError(401,"Unauthorized request")
     }
    
    const decodedTOken =  jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)
     
    const user = await  User.findById(decodedTOken?._id).select("-password -refereshToken")
    
    if(!user){
        throw new ApiError(401,"Invalid Acces Token")
    }
    req.user = user;
    next()
} catch (error) {
    throw new ApiError(401,error?.message||"Invalid access token")
}
})