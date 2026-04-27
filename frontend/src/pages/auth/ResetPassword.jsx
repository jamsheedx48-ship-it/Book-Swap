import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { resetPassword } from "../../api/auth";
import { toast } from "react-toastify";

const ResetPassword = () => {
    const [form, setForm] = useState({ code: "", new_password: "", confirm_password: "" });
    const [errors, setErrors] = useState({});
    const [loading, setLoading] = useState(false);

    const navigate = useNavigate();
    const location = useLocation();
    const email = location.state?.email;

    useEffect(() => {
        if (!email) navigate("/forgot-password");
    }, [email]);

    const handleChange = (e) => {
        setForm({ ...form, [e.target.name]: e.target.value });
        setErrors({ ...errors, [e.target.name]: "" });
    };

    const validate = () => {
        const newErrors = {};

        if (!form.code.trim()) {
            newErrors.code = "OTP is required.";
        } else if (form.code.length !== 6) {
            newErrors.code = "OTP must be 6 digits.";
        }
        if (!form.new_password) {
            newErrors.new_password = "Password is required.";
        } else if (form.new_password.length < 8) {
            newErrors.new_password = "Password must be at least 8 characters.";
        } else if (/^\d+$/.test(form.new_password)) {
            newErrors.new_password = "Password cannot be entirely numeric.";
        }
        if (!form.confirm_password) {
            newErrors.confirm_password = "Please confirm your password.";
        } else if (form.new_password !== form.confirm_password) {
            newErrors.confirm_password = "Passwords do not match.";
        }

        return newErrors;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        const validationErrors = validate();
        if (Object.keys(validationErrors).length > 0) {
            setErrors(validationErrors);
            return;
        }

        setLoading(true);
        try {
            await resetPassword({ email, code: form.code, new_password: form.new_password,confirm_password:form.confirm_password });
            toast.success("Password reset successfully. Please login.");
            navigate("/login");
        } catch (err) {
            const data = err.response?.data;
            if (data && typeof data === "object") {
                const backendErrors = {};
                for (const key in data) {
                    backendErrors[key] = Array.isArray(data[key])
                        ? data[key][0]
                        : data[key];
                }
                setErrors(backendErrors);
                if (backendErrors.error) {
                    toast.error(backendErrors.error);
                }
            } else {
                toast.error("Reset failed. Try again.");
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-ghost px-4">
            <div className="w-full max-w-md bg-white p-8 rounded-2xl shadow-lg">

                <h1 className="text-3xl font-bold text-persian mb-2">Reset password</h1>
                <p className="text-gray-500 mb-1">Enter the OTP sent to</p>
                <p className="text-persian font-medium mb-6">{email}</p>

                <form onSubmit={handleSubmit} className="flex flex-col gap-4">

                    <div>
                        <input
                            type="text"
                            name="code"
                            placeholder="Enter 6-digit OTP"
                            onChange={handleChange}
                            maxLength={6}
                            className="w-full border border-gray-300 px-4 py-3 rounded-lg focus:outline-none focus:border-persian tracking-widest text-center text-lg"
                        />
                        {errors.code && <p className="text-red-500 text-xs mt-1">{errors.code}</p>}
                    </div>

                    <div>
                        <input
                            type="password"
                            name="new_password"
                            placeholder="New password"
                            onChange={handleChange}
                            className="w-full border border-gray-300 px-4 py-3 rounded-lg focus:outline-none focus:border-persian"
                        />
                        {errors.new_password && <p className="text-red-500 text-xs mt-1">{errors.new_password}</p>}
                    </div>

                    <div>
                        <input
                            type="password"
                            name="confirm_password"
                            placeholder="Confirm new password"
                            onChange={handleChange}
                            className="w-full border border-gray-300 px-4 py-3 rounded-lg focus:outline-none focus:border-persian"
                        />
                        {errors.confirm_password && <p className="text-red-500 text-xs mt-1">{errors.confirm_password}</p>}
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="bg-persian text-white py-3 rounded-lg font-medium hover:opacity-90 transition disabled:opacity-50"
                    >
                        {loading ? "Resetting..." : "Reset Password"}
                    </button>

                </form>
            </div>
        </div>
    );
};

export default ResetPassword;