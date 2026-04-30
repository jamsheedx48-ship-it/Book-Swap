import axios from "axios"

const API= axios.create({
    baseURL:"http://localhost/api",
    withCredentials:true,
});

export const loginUser = (data)=> API.post("/users/login/",data);
export const registerUser = (data)=> API.post("/users/register/",data);
export const verifyOTP = (data)=> API.post("/users/verify-otp/",data);
export const resendOTP = (data)=> API.post("/users/resend-otp/",data)
export const forgotPassword = (data) => API.post("/users/forgot-password/", data);
export const resetPassword = (data) => API.post("/users/reset-password/", data);
export const mfaLoginVerify = (data) => API.post("/users/mfa/login-verify/", data);
export const getMe = () => API.get("/users/me/");
export const logoutUser = () => API.post("/users/logout/");

export default API;