import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { registerUser } from "../../api/auth";
import { toast } from "react-toastify";
import GoogleAuthButton from "../../components/GoogleAuthButton";

const Register = () => {
    const [form, setForm] = useState({
        name: "",
        email: "",
        password: "",
        confirm_password: ""
    });

    const [errors, setErrors] = useState({});
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleChange = (e) => {
        setForm({ ...form, [e.target.name]: e.target.value });
        setErrors({ ...errors, [e.target.name]: "" });
    };

    const validate = () => {
        const newErrors = {};  // fixed typo

        if (!form.name.trim()) {
            newErrors.name = "Name is required.";
        }

        if (!form.email.trim()) {
            newErrors.email = "Email is required.";
        } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) {
            newErrors.email = "Enter a valid email address.";
        }

        if (!form.password) {
            newErrors.password = "Password is required.";
        } else if (form.password.length < 8) {
            newErrors.password = "Password must be at least 8 characters.";
        } else if (/^\d+$/.test(form.password)) {
            newErrors.password = "Password cannot be entirely numeric.";
        }

        if (!form.confirm_password) {
            newErrors.confirm_password = "Please confirm your password.";
        } else if (form.password !== form.confirm_password) {
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
            await registerUser(form);
            toast.success("Account created! Please check your email for the OTP.")
            navigate("/verify-otp",{state:{email:form.email}});
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
                if (backendErrors.non_field_errors) {
                    toast.error(backendErrors.non_field_errors);
                }
            } else {
                toast.error("Registration failed. Try again.");

            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-ghost px-4">
            <div className="w-full max-w-md bg-white p-8 rounded-2xl shadow-lg">

                <h1 className="text-3xl font-bold text-persian mb-2">Create account</h1>
                <p className="text-gray-500 mb-6">Start your journey with us</p>
                 <GoogleAuthButton text="Sign up with Google" />
                

                <form onSubmit={handleSubmit} className="flex flex-col gap-4">

                    <div>
                        <input
                            type="text"
                            name="name"
                            placeholder="Full name"
                            onChange={handleChange}
                            className="w-full border border-gray-300 px-4 py-3 rounded-lg focus:outline-none focus:border-persian"
                        />
                        {errors.name && <p className="text-red-500 text-xs mt-1">{errors.name}</p>}
                    </div>

                    <div>
                        <input
                            type="email"
                            name="email"
                            placeholder="Email address"
                            onChange={handleChange}
                            className="w-full border border-gray-300 px-4 py-3 rounded-lg focus:outline-none focus:border-persian"
                        />
                        {errors.email && <p className="text-red-500 text-xs mt-1">{errors.email}</p>}
                    </div>

                    <div>
                        <input
                            type="password"
                            name="password"
                            placeholder="Password"
                            onChange={handleChange}
                            className="w-full border border-gray-300 px-4 py-3 rounded-lg focus:outline-none focus:border-persian"
                        />
                        {errors.password && <p className="text-red-500 text-xs mt-1">{errors.password}</p>}
                    </div>

                    <div>
                        <input
                            type="password"
                            name="confirm_password"
                            placeholder="Confirm password"
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
                        {loading ? "Creating..." : "Register"}
                    </button>

                    <p className="text-sm text-gray-500 mt-6 text-center">
                        Already have an account?{" "}
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

export default Register;