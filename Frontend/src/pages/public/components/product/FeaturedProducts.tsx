import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Carousel, CarouselContent, CarouselItem, CarouselNext, CarouselPrevious } from "@/components/ui/carousel";
import { TitleDecor } from "@/lib/iconsCustom";
import { Button } from "@/components/ui/button";
import ProductCard from "./ProductCard";
import { handleUpClick } from "@/lib/utils";
import { getProducts } from "../../services/productService";
import { CarouselApi, Product } from "@/types/types";

export default function FeaturedProducts() {
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const navigate = useNavigate();
  const [api, setApi] = useState<CarouselApi | null>(null);

  useEffect(() => {
    const fetchFeaturedProducts = async () => {
      try {
        const response = await getProducts({ is_featured: 1 });
        setProducts(response.data);
      } catch (error) {
        console.error("Error al obtener productos:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchFeaturedProducts();
  }, []);

  const handleProductClick = (id: number) => {
    navigate(`/product/${id}`);
    handleUpClick();
  };

  useEffect(() => {
    if (!api) return;
    const interval = setInterval(() => {
      api.scrollNext();
    }, 3000);

    return () => clearInterval(interval);
  }, [api]);

  if (loading) {
    return <div>Cargando productos...</div>;
  }

  return (
    <div className="bg-foreground py-12 px-4 lg:px-[120px]">
      <div className="text-center mb-12">
        <TitleDecor className="h-8 w-8 text-primary mx-auto mb-2" />
        <p className="text-primary font-medium mb-4">Sabor y Salud en Cada Bocado</p>
        <h2 className="text-3xl font-bold text-card-foreground sm:text-4xl mb-4">Nuestros productos destacados</h2>
      </div>

      <Carousel className="w-full mx-auto" setApi={(api) => setApi(api as CarouselApi)}>
        <CarouselContent className="gap-4">
          {products.map((product) => (
            <CarouselItem key={product.id} className="md:basis-1/2 lg:basis-1/4 2xl:basis-1/5">
              <ProductCard product={product} onClick={() => handleProductClick(product.id)} />
            </CarouselItem>
          ))}
        </CarouselContent>
        <CarouselPrevious />
        <CarouselNext />
      </Carousel>

      <div className="text-center mt-8">
        <Link to="/store">
          <Button variant="outline" className="bg-primary text-white px-8 py-2">
            Ver más productos
          </Button>
        </Link>
      </div>
    </div>
  );
}
