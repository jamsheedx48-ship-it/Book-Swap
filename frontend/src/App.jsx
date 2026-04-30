import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Register from "./pages/auth/Register";
import VerifyOTP from "./pages/auth/VerifyOTP";
import Login from "./pages/auth/Login";
import Dashboard from "./pages/auth/Dashboard";
import ForgotPassword from "./pages/auth/ForgotPassword";
import ResetPassword from "./pages/auth/ResetPassword";
import MFALoginVerify from "./pages/auth/MFALoginVerify";
import ChatList from "./pages/chat/ChatList";
import ChatRoom from "./pages/chat/ChatRoom";

export default function App(){
  return (
    <BrowserRouter>
     <Routes>
        {/* auth */}
       <Route path="/register" element={<Register/>}/>
       <Route path="/login" element={<Login/>}/>
       <Route path="/verify-otp" element={<VerifyOTP/>}/>
       <Route path="/dashboard" element={<Dashboard />} />
       <Route path="/forgot-password" element={<ForgotPassword/>} />
       <Route path="/reset-password" element={<ResetPassword/>} />
       <Route path="/mfa-verify" element={<MFALoginVerify/>} />
       {/* chat */}
       <Route path="/chat" element={<ChatList/>}/>
       <Route path="/chat/:conversationId" element={<ChatRoom/>}/>

     </Routes>
    </BrowserRouter>
  )
}