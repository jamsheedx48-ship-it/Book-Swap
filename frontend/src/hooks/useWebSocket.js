import { useEffect, useRef, useCallback } from "react";

const WS_BASE_URL = "ws://localhost:80/ws/chat";

const useWebSocket = (conversationId, onMessage) => {
    const ws = useRef(null);

    const connect = useCallback(() => {
        ws.current = new WebSocket(`${WS_BASE_URL}/${conversationId}/`);

        ws.current.onopen = () => {
            console.log("WebSocket connected");
        };

        ws.current.onmessage = (event) => {
            const data = JSON.parse(event.data);
            onMessage(data);
        };

        ws.current.onclose = () => {
            console.log("WebSocket disconnected");
        };

        ws.current.onerror = (error) => {
            console.error("WebSocket error:", error);
        };
    }, [conversationId, onMessage]);

    useEffect(() => {
        connect();
        return () => {
            if (ws.current) ws.current.close();
        };
    }, [connect]);

    const sendMessage = useCallback((message) => {
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
            ws.current.send(JSON.stringify({ message }));
        }
    }, []);

    return { sendMessage };
};

export default useWebSocket;