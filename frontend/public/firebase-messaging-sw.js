importScripts(
  "https://www.gstatic.com/firebasejs/10.13.2/firebase-app-compat.js"
);

importScripts(
  "https://www.gstatic.com/firebasejs/10.13.2/firebase-messaging-compat.js"
);

firebase.initializeApp({
  apiKey: "AIzaSyA_5aRJt-91un80fsEsglSt8_2UblJXfz0",
  authDomain: "bookswap-cb1a5.firebaseapp.com",
  projectId: "bookswap-cb1a5",
  storageBucket: "bookswap-cb1a5.firebasestorage.app",
  messagingSenderId: "955488952543",
  appId: "1:955488952543:web:35b9d11d0ccb36d71f096a",
});

const messaging = firebase.messaging();

messaging.onBackgroundMessage((payload) => {
  console.log("Background message received:", payload);
  self.registration.showNotification(
    payload.notification?.title || "New Notification",
    {
      body: payload.notification?.body || "",
      icon: "/favicon.ico",
    }
  );
});

// // Handle push event directly
// self.addEventListener("push", (event) => {
//   console.log("Push event received:", event);
//   const data = event.data?.json() || {};
//   event.waitUntil(
//     self.registration.showNotification(data.notification?.title || "Book Swap", {
//       body: data.notification?.body || "",
//       icon: "/favicon.ico",
//     })
//   );
// });