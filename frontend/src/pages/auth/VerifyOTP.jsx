import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { verifyOTP, resendOTP } from "../../api/auth";
import { toast } from "react-toastify";

const VerifyOTP = () => {
    const [code, setCode] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);
    const [resendLoading, setResendLoading] = useState(false);
    const [cooldown, setCooldown] = useState(60);

    const navigate = useNavigate();
    const location = useLocation();
    const email = location.state?.email;

    // redirect if no email in state
    useEffect(() => {
        if (!email) navigate("/register");
    }, [email]);

    // cooldown timer
    useEffect(() => {
        if (cooldown <= 0) return;
        const timer = setTimeout(() => setCooldown(cooldown - 1), 1000);
        return () => clearTimeout(timer);
    }, [cooldown]);

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!code.trim()) {
            setError("Please enter the OTP.");
            return;
        }
        if (code.length !== 6) {
            setError("OTP must be 6 digits.");
            return;
        }

        setLoading(true);
        setError("");
        try {
            await verifyOTP({ email, code });
            toast.success("Email verified! You can now log in.");
            navigate("/login");
        } catch (err) {
            const data = err.response?.data;
            setError(data?.error || "Verification failed. Try again.");
        } finally {
            setLoading(false);
        }
    };

    const handleResend = async () => {
        if (cooldown > 0) return;

        setResendLoading(true);
        try {
            await resendOTP({ email });
            toast.success("OTP resent to your email.");
            setCooldown(60);
        } catch (err) {
            const data = err.response?.data;
            toast.error(data?.error || "Failed to resend OTP.");
            // if backend returns wait time, start cooldown anyway
            setCooldown(60);
        } finally {
            setResendLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-ghost px-4">
            <div className="w-full max-w-md bg-white p-8 rounded-2xl shadow-lg">

                <h1 className="text-3xl font-bold text-persian mb-2">Verify your email</h1>
                <p className="text-gray-500 mb-1">We sent a 6-digit OTP to</p>
                <p className="text-persian font-medium mb-6">{email}</p>

                <form onSubmit={handleSubmit} className="flex flex-col gap-4">
                    <div>
                        <input
                            type="text"
                            placeholder="Enter 6-digit OTP"
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
                        {loading ? "Verifying..." : "Verify OTP"}
                    </button>

                    <button
                        type="button"
                        onClick={handleResend}
                        disabled={resendLoading || cooldown > 0}
                        className="text-sm text-persian font-medium disabled:opacity-50 hover:underline"
                    >
                        {cooldown > 0
                            ? `Resend OTP in ${cooldown}s`
                            : resendLoading
                            ? "Sending..."
                            : "Resend OTP"}
                    </button>
                </form>
            </div>
        </div>
    );
};

export default VerifyOTP;