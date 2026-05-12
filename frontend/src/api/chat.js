import api from "./axiosInstance";

export const getConversations = () => api.get("chat/conversations/");
export const startConversation = (userId) => api.post("chat/conversations/start/", { user_id: userId });
export const getMessages = (conversationId) => api.get(`chat/conversations/${conversationId}/messages/`);