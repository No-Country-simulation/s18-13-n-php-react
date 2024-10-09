import products from "@/api/products.json";
import { Product } from "@/types/types";
import ProductCard from "./ProductCard";

const typedProducts: ReadonlyArray<Product> = products as ReadonlyArray<Product>;

export default function ProductList() {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 p-4">
      {typedProducts.map((product) => (
        <ProductCard key={product.id} product={product} />
      ))}
    </div>
  );
}
