import api from "./axiosInstance";

export const loginUser = (data) => api.post("users/login/", data);
export const registerUser = (data) => api.post("users/register/", data);
export const verifyOTP = (data) => api.post("users/verify-otp/", data);
export const resendOTP = (data) => api.post("users/resend-otp/", data);
export const forgotPassword = (data) => api.post("users/forgot-password/", data);
export const resetPassword = (data) => api.post("users/reset-password/", data);

// mfa
export const mfaLoginVerify = (data) => api.post("users/mfa/login-verify/", data);
export const getMFAStatus = () => api.get("users/mfa/status/");
export const setupMFA = () => api.post("users/mfa/setup/");
export const verifyMFASetup = (data) => api.post("users/mfa/verify-setup/", data);
export const disableMFA = (data) => api.post("users/mfa/disable/", data);

export const getMe = () => api.get("users/me/");
export const logoutUser = () => api.post("users/logout/");
export const updateFCMToken = (fcm_token) => api.patch("users/fcm-token/", { fcm_token });