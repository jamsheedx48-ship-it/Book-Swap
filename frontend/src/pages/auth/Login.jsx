import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { loginUser, resendOTP, updateFCMToken } from "../../api/auth";
import { toast } from "react-toastify";
import GoogleAuthButton from "../../components/GoogleAuthButton";
import { requestFCMToken } from "../../firebase";

const Login = () => {
  const [form, setForm] = useState({ email: "", password: "" });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
    setErrors({ ...errors, [e.target.name]: "" });
  };

  const validate = () => {
    const newErrors = {};
    if (!form.email.trim()) {
      newErrors.email = "Email is required.";
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) {
      newErrors.email = "Enter a valid email address.";
    }
    if (!form.password) {
      newErrors.password = "Password is required.";
    }
    return newErrors;
  };

  const saveFCMToken = async () => {
    try {
      const token = await requestFCMToken();
      console.log("FCM token result:", token);
      if (token) {
        await updateFCMToken(token);
        console.log("FCM token saved");
      }
    } catch (err) {
      console.error("FCM token save failed:", err);
    }
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
      const res = await loginUser(form);
      const data = res.data;

      // MFA required
      if (data.mfa_required) {
        navigate("/mfa-verify", { state: { temp_token: data.temp_token } });
        return;
      }
      
      await saveFCMToken();
      // success
      toast.success(`Welcome back, ${data.name}!`);
      navigate("/dashboard");
    } catch (err) {
      const data = err.response?.data;

      // email not verified → go to verify-otp
      if (err.response?.status === 403) {
        try {
          await resendOTP({ email: form.email });
          toast.info("OTP sent to your email. Please verify.");
          navigate("/verify-otp", { state: { email: form.email } });
        } catch (resendErr) {
          const resendData = resendErr.response?.data;
          toast.error(resendData?.error || "Could not send OTP. Try again.");
        }
        return;
      }

      // field errors from serializer
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
        toast.error("Login failed. Try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-ghost px-4">
      <div className="w-full max-w-md bg-white p-8 rounded-2xl shadow-lg">
        <h1 className="text-3xl font-bold text-persian mb-2">Welcome back</h1>
        <p className="text-gray-500 mb-6">Login to your account</p>
        <GoogleAuthButton text="Login with Google" />

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <input
              type="email"
              name="email"
              placeholder="Email address"
              onChange={handleChange}
              className="w-full border border-gray-300 px-4 py-3 rounded-lg focus:outline-none focus:border-persian"
            />
            {errors.email && (
              <p className="text-red-500 text-xs mt-1">{errors.email}</p>
            )}
          </div>

          <div>
            <input
              type="password"
              name="password"
              placeholder="Password"
              onChange={handleChange}
              className="w-full border border-gray-300 px-4 py-3 rounded-lg focus:outline-none focus:border-persian"
            />
            {errors.password && (
              <p className="text-red-500 text-xs mt-1">{errors.password}</p>
            )}
          </div>

          <div className="text-right">
            <span
              onClick={() => navigate("/forgot-password")}
              className="text-sm text-persian cursor-pointer hover:underline"
            >
              Forgot password?
            </span>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="bg-persian text-white py-3 rounded-lg font-medium hover:opacity-90 transition disabled:opacity-50"
          >
            {loading ? "Logging in..." : "Login"}
          </button>

          <p className="text-sm text-gray-500 mt-6 text-center">
            Don't have an account?{" "}
            <span
              onClick={() => navigate("/register")}
              className="text-persian cursor-pointer font-medium"
            >
              Register
            </span>
          </p>
        </form>
      </div>
    </div>
  );
};

export default Login;
