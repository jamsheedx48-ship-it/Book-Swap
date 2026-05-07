import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";

export default function OAuthCallback() {
  const navigate = useNavigate();

  useEffect(() => {
    toast.success("Signed in with Google successfully!");
    window.location.href="/dashboard";
  }, []);

  return (
    <div className="flex items-center justify-center h-screen bg-[#F6F7FF]">
      <p className="text-[#26187D] text-lg font-medium">Signing you in...</p>
    </div>
  );
}