import express from "express";
import { loginOrSignUp, refreshToken, registerWithEmail, loginWithEmail, getUserProfile, updateUserProfile } from "../controllers/user.js";

const router = express.Router();

router.post("/login", loginOrSignUp);
router.post("/register", registerWithEmail);
router.post("/login-email", loginWithEmail);
router.get("/profile", getUserProfile);
router.put("/profile", updateUserProfile);
router.post("/refresh", refreshToken);

export default router;
