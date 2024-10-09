import NotFound from "@/pages/public/error/NotFound";
import Home from "@/pages/public/home/Home";
import ProductList from "@/pages/public/product/ProductList";
import { Route, Routes } from "react-router-dom";

export default function PublicRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="store" element={<ProductList />} />

      {/* Ruta para manejar errores 404 */}
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
