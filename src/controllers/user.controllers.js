import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import  jwt from "jsonwebtoken"


const generateAccessAndRefereshTokens = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken =   user.generateAccessToken()
        const refereshToken = user.generateRefreshToken()

        user.refereshToken = refereshToken
        await user.save({validateBefreSave:false})

        return {accessToken,refereshToken}

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating referesh and access token")
    }
}



const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res


    const { fullName, email, username, password } = req.body

    //console.log("email: ", email);
    // console.log(req.body);

    if (
        [fullName, email, username, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }
    // console.log(req.files);

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;


    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }



    //console.log(req.files?.avatar[0]?.path)

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }


    const user = await User.create({
        fullName,
        avatar: avatar?.url || "",
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered Successfully")
    )

})

const loginUser = asyncHandler(async (req, res) => {
    // req or body -> data
    // username or email 
    //  find the user
    // password  check 
    // access and refresh token
    // send cookie


    const { email, username, password } = req.body

    if (!username && !email) {
        throw new ApiError(400, "username or email is required")
    }

    const user = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)

    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user credentials")
    }

  const{accessToken,refereshToken} = await generateAccessAndRefereshTokens(user._id)

const loggedInUser = await User.findById(user._id).select("-password  -refreshToken")

const options = {
    httpOnly:true,
    secure:true
};
return res
.status(200)
.cookie("accessToken",accessToken,options)
.cookie("refereshToken",refereshToken,options)
.json(
    new ApiResponse(
        200,
        {
            user: loggedInUser,accessToken,
            refereshToken
        },
        "User logged In Successfully"
    )
)
})


const logoutUser = asyncHandler(async(req,res)=>{
await User.findByIdAndUpdate(
    req.user._id,
    {
        $set:{
         refreshToken   :undefined
        }
    },
    {
        new: true
    }
)
const options = {
    httpOnly:true,
    secure:true
};

return res
.status(200)
.clearCookie("accessToken",options)
.clearCookie("refereshToken",options)
.json(new ApiResponse(200,{},"User logged Out"))
})


const refereshAccessToken=asyncHandler(async(req,res)=>{
 const incomingRefreshToken = req.cookie.refereshToken || req.body.refereshToken

 if(incomingRefreshToken){
    throw new ApiError(401,"unauthorized request")
 }

try {
     const decodedToken =  jwt.verify(
        incomingRefreshToken,
        process.env.REFRESH_TOKEN_SECRET
     )
    
    const user = await User.findById(decodedToken?._id)
    
     if(!user){
        throw new ApiError(401,"Invalid refresh token")
     }
    
     if(incomingRefreshToken!==user?.refereshToken){
        throw new  ApiError(401,"Refresh token is expired or used")
     }
     const options = {
        httpOnly:true,
        secure:true
     }
    const{accessToken,newrefreshToken}=await generateAccessAndRefereshTokens(user._id)
    
    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",newrefreshToken,options)
    .json(
        new ApiResponse(
            {accessToken,refreshToken:newrefreshToken},
            "Access Token refresh"
        )
    )
     
} catch (error) {
    throw new ApiError(401,error?.message || "Invalid refresh token")
}
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refereshAccessToken
} 