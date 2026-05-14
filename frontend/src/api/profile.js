import api from "./axiosInstance";

// Fetch current logged-in user's profile
export const getMyProfile = () => api.get("profile/me/");

// Fetch a public profile by ID
export const getPublicProfile = (userId) => api.get(`profile/${userId}/`);

// Update profile details (bio, location, avatar, interests)
export const updateProfile = (profileData) => {
    const isFormData = profileData instanceof FormData;
    return api.patch("profile/me/", profileData, {
        headers: isFormData ? { 'Content-Type': 'multipart/form-data' } : {},
    });
};

// Fetch all genres available for interest selection
export const getGenres = () => api.get("profile/genres/");

// --- Rating & Review Endpoints ---

// Get all ratings received by a specific user
export const getUserRatings = (userId) => api.get(`profile/${userId}/ratings/`);

// Submit a new rating for a user
// ratingData should include { score, comment }
export const submitRating = (userId, ratingData) => api.post(`profile/${userId}/ratings/submit/`, ratingData);

// Delete your previous rating for a user
export const deleteRating = (userId) => api.delete(`profile/${userId}/ratings/delete/`);

export const getRecentActivity = () => api.get("profile/activity/");

export const changePassword = (data) => api.post("users/change-password/", data);

