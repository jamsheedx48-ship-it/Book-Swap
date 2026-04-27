import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { forgotPassword,resendOTP } from "../../api/auth";
import { toast } from "react-toastify";

const ForgotPassword = () => {
    const [email, setEmail] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!email.trim()) {
            setError("Email is required.");
            return;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            setError("Enter a valid email address.");
            return;
        }

        setLoading(true);
        try {
            await forgotPassword({ email });
            toast.success("OTP sent to your email.");
            navigate("/reset-password", { state: { email } });
        } catch (err) {
            if (err.response?.status === 403) {
                try {
                    await resendOTP({ email });
                    toast.info("OTP sent to your email. Please verify first.");
                    navigate("/verify-otp", { state: { email } });
                } catch (resendErr) {
                    const resendData = resendErr.response?.data;
                    toast.error(resendData?.error || "Could not send OTP. Try again.");
                }
                return;
            }
            const data = err.response?.data;
            setError(data?.error || "Something went wrong. Try again.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-ghost px-4">
            <div className="w-full max-w-md bg-white p-8 rounded-2xl shadow-lg">

                <h1 className="text-3xl font-bold text-persian mb-2">Forgot password</h1>
                <p className="text-gray-500 mb-6">Enter your email and we'll send you an OTP</p>

                <form onSubmit={handleSubmit} className="flex flex-col gap-4">
                    <div>
                        <input
                            type="email"
                            placeholder="Email address"
                            value={email}
                            onChange={(e) => {
                                setEmail(e.target.value);
                                setError("");
                            }}
                            className="w-full border border-gray-300 px-4 py-3 rounded-lg focus:outline-none focus:border-persian"
                        />
                        {error && <p className="text-red-500 text-xs mt-1">{error}</p>}
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="bg-persian text-white py-3 rounded-lg font-medium hover:opacity-90 transition disabled:opacity-50"
                    >
                        {loading ? "Sending..." : "Send OTP"}
                    </button>

                    <p className="text-sm text-gray-500 text-center">
                        Remember your password?{" "}
                        <span
                            onClick={() => navigate("/login")}
                            className="text-persian cursor-pointer font-medium"
                        >
                            Login
                        </span>
                    </p>
                </form>
            </div>
        </div>
    );
};

export default ForgotPassword;