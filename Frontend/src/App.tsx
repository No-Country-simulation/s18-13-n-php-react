import { Route, Routes } from "react-router-dom";
import { AdminRoutes, ClientRoutes, ProducerRoutes, PublicRoutes } from "./routes";
import ProtectedLayout from "./components/layout/ProtectedLayout";
import PublicLayout from "./components/layout/PublicLayout";
import useDarkMode from "./hooks/useDarkMode";

function App() {
  useDarkMode();
  return (
    <>
      <Routes>
        {/* Rutas públicas */}
        <Route
          path="/*"
          element={
            <PublicLayout>
              <PublicRoutes />
            </PublicLayout>
          }
        />

        {/* Rutas Privadas para Admin */}
        <Route
          path="/admin/*"
          element={
            <ProtectedLayout>
              <AdminRoutes />
            </ProtectedLayout>
          }
        />

        {/* Rutas Privadas para Cliente */}
        <Route
          path="/client/*"
          element={
            <ProtectedLayout>
              <ClientRoutes />
            </ProtectedLayout>
          }
        />

        {/* Rutas Privadas para Productor */}
        <Route
          path="/producer/*"
          element={
            <ProtectedLayout>
              <ProducerRoutes />
            </ProtectedLayout>
          }
        />
      </Routes>
    </>
  );
}

export default App;
