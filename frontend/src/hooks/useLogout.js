import { useNavigate } from "react-router-dom";
import { logoutUser } from "../api/auth";
import { toast } from "react-toastify";

const useLogout = () => {
    const navigate = useNavigate();

    const logout = async () => {
        try {
            await logoutUser();
            toast.success("Logged out successfully.");
        } catch (err) {
            // even if it fails, clear and redirect
            toast.error("Something went wrong, logging out anyway.");
        } finally {
            navigate("/login");
        }
    };

    return logout;
};

export default useLogout;