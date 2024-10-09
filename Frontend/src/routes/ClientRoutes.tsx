import ClientDashboard from "@/pages/client/dashboard/ClientDashboard";
import { Route, Routes } from "react-router-dom";

export default function ClientRoutes() {
  return (
    <Routes>
      <Route path="dashboard" element={<ClientDashboard />} />
      {/* Aquí puedes añadir más rutas para clientes */}
    </Routes>
  );
}
