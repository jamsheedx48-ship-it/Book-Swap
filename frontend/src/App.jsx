import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import ProtectedRoute from "./routes/ProtectedRoute";
import Register from "./pages/auth/Register";
import VerifyOTP from "./pages/auth/VerifyOTP";
import Login from "./pages/auth/Login";
import Dashboard from "./pages/auth/Dashboard";
import ForgotPassword from "./pages/auth/ForgotPassword";
import ResetPassword from "./pages/auth/ResetPassword";
import MFALoginVerify from "./pages/auth/MFALoginVerify";
import ChatList from "./pages/chat/ChatList";
import ChatRoom from "./pages/chat/ChatRoom";
import ListBook from "./pages/books/ListBook";
import BrowseBooks from "./pages/books/BrowseBooks";
import BookDetail from "./pages/books/BookDetail";
import OAuthCallback from "./pages/auth/OAuthCallback";
import MyExchanges from "./pages/exchanges/MyExchanges";
import MyListings from "./pages/books/MyListings";
import MFASettings from "./pages/mfa/MFASettings";
import TrashBooks from "./pages/books/TrashBooks";

import { requestFCMToken } from "./firebase";
import { useEffect } from "react";
import ProfilePage from "./pages/profile/ProfilePage";
import SettingsPage from "./pages/profile/SettingsPage";
import NotificationsPage from "./pages/profile/NotificationsPage";
import { NotificationProvider } from "./context/NotificationContext";

export default function App(){
  useEffect(()=>{
    requestFCMToken().then(token=>console.log("TOKEN:", token))
  },[])
  return (
    <BrowserRouter>
     <NotificationProvider>
     <Routes>
       <Route path="/" element={<Dashboard/>}/>
        {/* auth */}
       <Route path="/register" element={<Register/>}/>
       <Route path="/login" element={<Login/>}/>
       <Route path="/verify-otp" element={<VerifyOTP/>}/>
       <Route path="/dashboard" element={<Dashboard />} />
       <Route path="/forgot-password" element={<ForgotPassword/>} />
       <Route path="/reset-password" element={<ResetPassword/>} />
       <Route path="/mfa-verify" element={<MFALoginVerify/>} />
       <Route path="/oauth/callback" element={<OAuthCallback />} />


       {/* chat */}
       <Route path="/chat" element={<ProtectedRoute><ChatList/></ProtectedRoute>}/>
       <Route path="/chat/:conversationId" element={<ProtectedRoute><ChatRoom/></ProtectedRoute>}/>

       {/* books */}
       <Route path="/browse-books" element={<BrowseBooks/>} />
       <Route path="/my-listings" element={<ProtectedRoute><MyListings/></ProtectedRoute>} />
       <Route path="/list-book" element={<ProtectedRoute><ListBook/></ProtectedRoute>} />
       <Route path="/books/:id" element={<BookDetail />} />

       <Route path="/exchanges" element={<ProtectedRoute><MyExchanges/></ProtectedRoute>}/>
       
       <Route path="/settings/security/mfa" element={<MFASettings/>} />
       
       <Route path="/trash-books" element={<TrashBooks/>} />

       {/* Profile */}
       <Route path="/profile" element={<ProfilePage/>}/>
       <Route path="/settings" element={<SettingsPage/>}/>

       <Route path="/notifications" element={<NotificationsPage/>} />

       

     </Routes>
     </NotificationProvider>
    </BrowserRouter>
  )
}