import { createContext, useContext, useState, useEffect, useRef } from "react";
import { getNotifications } from "../api/notifications";

const NotificationContext = createContext(null);

export function NotificationProvider({ children }) {
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const ws = useRef(null);

  useEffect(() => {
    ws.current = new WebSocket(`ws://localhost:80/ws/notifications/`);

    ws.current.onopen = () => console.log("Notification WS connected");

    ws.current.onmessage = (e) => {
      const data = JSON.parse(e.data);
      console.log("WS notification received:", data); // add this
      if (data.type === "unread_count") setUnreadCount(data.count);
      if (data.type === "notification") {
        setUnreadCount((prev) => prev + 1);
        setNotifications((prev) => [data, ...prev]);
      }
    };

    ws.current.onerror = (e) => console.error("Notification WS error:", e);

    getNotifications()
      .then((res) => setNotifications(res.data))
      .catch((err) => console.error("fetch error:", err));

    return () => ws.current?.close();
  }, []);

  const markAllRead = () => {
    ws.current?.send(JSON.stringify({ action: "mark_read" }));
    setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true })));
    setUnreadCount(0);
  };

//   const markMessagesRead = () => {
//     setNotifications((prev) =>
//       prev.map((n) =>
//         n.notification_type === "message" ? { ...n, is_read: true } : n,
//       ),
//     );
//   };

  return (
    <NotificationContext.Provider
      value={{ notifications, unreadCount, markAllRead }}
    >
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotifications() {
  return useContext(NotificationContext);
}
