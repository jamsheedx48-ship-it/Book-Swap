importScripts(
  "https://www.gstatic.com/firebasejs/10.13.2/firebase-app-compat.js"
);

importScripts(
  "https://www.gstatic.com/firebasejs/10.13.2/firebase-messaging-compat.js"
);

firebase.initializeApp({
  apiKey: "import.meta.env.VITE_FIREBASE_API_KEY",
  authDomain: "bookswap-cb1a5.firebaseapp.com",
  projectId: "bookswap-cb1a5",
  storageBucket: "bookswap-cb1a5.firebasestorage.app",
  messagingSenderId: "955488952543",
  appId: "1:955488952543:web:35b9d11d0ccb36d71f096a",
});
