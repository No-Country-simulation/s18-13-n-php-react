import AdminDashboard from "@/pages/admin/dashboard/AdminDashboard";
import { Route, Routes } from "react-router-dom";

export default function AdminRoutes() {
  return (
    <Routes>
      <Route path="dashboard" element={<AdminDashboard />} />
      {/* Aquí puedes añadir más rutas para el administrador */}
    </Routes>
  );
}
