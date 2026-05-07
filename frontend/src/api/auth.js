import axios from "axios"

const API= axios.create({
    baseURL:"http://localhost/api/users",
    withCredentials:true,
});

export const loginUser = (data)=> API.post("/login/",data);
export const registerUser = (data)=> API.post("/register/",data);
export const verifyOTP = (data)=> API.post("/verify-otp/",data);
export const resendOTP = (data)=> API.post("/resend-otp/",data)
export const forgotPassword = (data) => API.post("/forgot-password/", data);
export const resetPassword = (data) => API.post("/reset-password/", data);
export const mfaLoginVerify = (data) => API.post("/mfa/login-verify/", data);
export const getMe = () => API.get("/me/");
export const logoutUser = () => API.post("/logout/");
export const updateFCMToken =(fcm_token)=>API.patch("/fcm-token/",{fcm_token});
export default API;