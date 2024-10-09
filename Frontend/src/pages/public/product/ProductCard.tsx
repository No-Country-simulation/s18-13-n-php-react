import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ShoppingCart } from "lucide-react";
import { formatPrice, generateEAN8SKUFromID } from "@/lib/utils";
import { Product } from "@/types/types";

interface ProductCardProps {
  product: Product;
}

export default function ProductCard({ product }: ProductCardProps) {
  return (
    <Card>
      <CardHeader>
        <img src={product.product_picture} alt={product.description} width={200} height={200} className="w-full h-auto object-cover" />
      </CardHeader>
      <CardContent>
        <div className="mt-2">SKU: {generateEAN8SKUFromID(product.id)}</div>
        <span className="block text-lg font-semibold mt-2 h-20">{product.description}</span>
        <div className="flex justify-between items-center mt-4">
          <span className="text-lg font-semibold text-destructive">{formatPrice(product.price)}</span>
          <Button aria-label={`Agregar ${product.description} al carrito`}>
            <ShoppingCart className="mr-2 h-4 w-4" />
            Agregar
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
