import React from "react";

const GoogleAuthButton = ({ text = "Continue with Google" }) => {
  const handleGoogleLogin = () => {
    window.location.href = "http://localhost/auth/login/google-oauth2/";
  };

  return (
    <>
      <button
        onClick={handleGoogleLogin}
        type="button"
        className="w-full flex items-center justify-center gap-3 border border-gray-300 rounded-lg py-3 font-medium hover:bg-gray-50 transition"
      >
        <img
          src="https://www.svgrepo.com/show/475656/google-color.svg"
          alt="Google"
          className="w-5 h-5"
        />
        {text}
      </button>

      {/* Divider */}
      <div className="flex items-center my-6">
        <div className="flex-1 h-px bg-gray-300"></div>
        <span className="px-3 text-sm text-gray-500">
          or continue with email
        </span>
        <div className="flex-1 h-px bg-gray-300"></div>
      </div>
    </>
  );
};

export default GoogleAuthButton;