import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { mfaLoginVerify } from "../../api/auth";
import { toast } from "react-toastify";

const MFALoginVerify = () => {
    const [code, setCode] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    const navigate = useNavigate();
    const location = useLocation();
    const temp_token = location.state?.temp_token;

    useEffect(() => {
        if (!temp_token) navigate("/login");
    }, [temp_token]);

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!code.trim()) {
            setError("Please enter the code.");
            return;
        }
        if (code.length !== 6) {
            setError("Code must be 6 digits.");
            return;
        }

        setLoading(true);
        setError("");
        try {
          const res = await mfaLoginVerify({ temp_token, code });
          toast.success(`Welcome back, ${res.data.name}!`);
          navigate("/dashboard");
        } catch (err) {
          const data = err.response?.data;

          if (data?.detail === "Session expired or invalid token.") {
            toast.error("Session expired. Please login again.");
            navigate("/login");
            return;
          }

          setError(
            data?.detail || data?.error || "Verification failed. Try again.",
          );
        } finally {
          setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-ghost px-4">
            <div className="w-full max-w-md bg-white p-8 rounded-2xl shadow-lg">

                <h1 className="text-3xl font-bold text-persian mb-2">Two-factor auth</h1>
                <p className="text-gray-500 mb-6">Enter the 6-digit code from your authenticator app</p>

                <form onSubmit={handleSubmit} className="flex flex-col gap-4">
                    <div>
                        <input
                            type="text"
                            placeholder="Enter 6-digit code"
                            value={code}
                            onChange={(e) => {
                                setCode(e.target.value);
                                setError("");
                            }}
                            maxLength={6}
                            className="w-full border border-gray-300 px-4 py-3 rounded-lg focus:outline-none focus:border-persian tracking-widest text-center text-lg"
                        />
                        {error && <p className="text-red-500 text-xs mt-1">{error}</p>}
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="bg-persian text-white py-3 rounded-lg font-medium hover:opacity-90 transition disabled:opacity-50"
                    >
                        {loading ? "Verifying..." : "Verify"}
                    </button>

                    <p className="text-sm text-gray-500 text-center">
                        <span
                            onClick={() => navigate("/login")}
                            className="text-persian cursor-pointer font-medium"
                        >
                            Back to login
                        </span>
                    </p>
                </form>
            </div>
        </div>
    );
};

export default MFALoginVerify;