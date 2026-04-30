import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getConversations } from "../../api/chat";

const ChatList = () => {
    const [conversations, setConversations] = useState([]);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        getConversations()
            .then((res) => setConversations(res.data))
            .catch((err) => setError(err.response?.data?.detail || "Failed to load conversations."))
            .finally(() => setLoading(false));
    }, []);

    return (
        <div style={{ backgroundColor: "#F6F7FF", minHeight: "100vh", padding: "24px" }}>
            <h2 style={{ color: "#26187D", marginBottom: "24px", fontSize: "22px", fontWeight: "700" }}>
                Messages
            </h2>
            <div style={{ maxWidth: "600px", margin: "0 auto" }}>
                {loading && <p style={{ textAlign: "center", color: "#888" }}>Loading...</p>}
                {error && (
                    <p style={{ textAlign: "center", color: "red", fontSize: "14px" }}>{error}</p>
                )}
                {!loading && !error && conversations.length === 0 && (
                    <p style={{ color: "#888", textAlign: "center" }}>No conversations yet.</p>
                )}
                {conversations.map((conv) => (
                    <div
                        key={conv.id}
                        onClick={() => navigate(`/chat/${conv.id}`)}
                        style={{
                            backgroundColor: "#fff",
                            borderRadius: "12px",
                            padding: "16px 20px",
                            marginBottom: "12px",
                            cursor: "pointer",
                            boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            border: "1px solid #ebebf0",
                        }}
                    >
                        <div>
                            <p style={{ fontWeight: "600", color: "#1a1a2e", margin: 0 }}>
                                {conv.other_user?.name || "Unknown"}
                            </p>
                            <p style={{ color: "#888", fontSize: "13px", margin: "4px 0 0" }}>
                                {conv.last_message?.message || "No messages yet"}
                            </p>
                        </div>
                        <span style={{ color: "#26187D", fontSize: "20px" }}>›</span>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default ChatList;
