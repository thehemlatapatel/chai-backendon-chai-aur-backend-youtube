import { Router } from "express";
import { loginUser, logoutUser, registerUser } from "../controllers/user.controllers.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWt } from "../middlewares/auth.middleware.js";
import { refereshAccessToken } from "../controllers/user.controllers.js";

const router =Router()

router.route("/register").post(
    
    upload.fields([
{
    name:"avatar",
    maxCount:1
},
{
   name:"coverImage",
   maxCount:1
}
    ]),
    registerUser)

    router.route("/login").post(loginUser)
    // secured routers
    router.route("/logout").post( verifyJWt, logoutUser)
    router.route("/refresh-token").post(refereshAccessToken)



export default router