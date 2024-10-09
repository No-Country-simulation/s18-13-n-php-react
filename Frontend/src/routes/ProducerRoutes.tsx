import ProducerDashboard from "@/pages/producer/dashboard/ProducerDashboard";
import { Route, Routes } from "react-router-dom";

export default function ProducerRoutes() {
  return (
    <Routes>
      <Route path="dashboard" element={<ProducerDashboard />} />
      {/* Aquí puedes añadir más rutas para el productor */}
    </Routes>
  );
}
