import { Menu, Search, ShoppingCart } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { useEffect, useState } from "react";
import SearchModal from "./SearchModal";
import Logo from "./logo";

export default function PublicNavbar() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [searchModalOpen, setSearchModalOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 0);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <>
      <header
        className={`sticky top-0 z-50 w-full max-w-screen-2xl mx-auto lg:px-[120px] ${isScrolled ? "backdrop-blur supports-[backdrop-filter]" : ""}`}
      >
        <div className="container flex h-16 items-center justify-between p-4">
          <Logo />
          <nav className="hidden md:flex items-center space-x-4">
            <Button variant="link" asChild>
              <Link to="/">Inicio</Link>
            </Button>
            <Button variant="link" asChild>
              <Link to="/about">Sobre Nosotros</Link>
            </Button>
            <Button variant="link" asChild>
              <Link to="/store">Tienda</Link>
            </Button>
            <Button variant="link" asChild>
              <Link to="/events">Eventos</Link>
            </Button>
            <Button variant="link" asChild>
              <Link to="/contact">Contacto</Link>
            </Button>
          </nav>
          <div className="flex items-center space-x-4">
            <button className="text-button" aria-label="Buscar" onClick={() => setSearchModalOpen(true)}>
              <Search className="h-5 w-5" />
            </button>
            <Link to="/cart" aria-label="Carrito">
              <ShoppingCart className="h-5 w-5" />
            </Link>
            <Sheet>
              <SheetTrigger asChild>
                <button aria-label="Toggle Menu" className="md:hidden">
                  <Menu className="h-5 w-5" />
                </button>
              </SheetTrigger>
              <SheetContent side="right">
                <nav className="flex flex-col space-y-4">
                  <Button variant="link" asChild>
                    <Link to="/">Inicio</Link>
                  </Button>
                  <Button variant="link" asChild>
                    <Link to="/about">Sobre Nosotros</Link>
                  </Button>
                  <Button variant="link" asChild>
                    <Link to="/store">Tienda</Link>
                  </Button>
                  <Button variant="link" asChild>
                    <Link to="/contact">Contacto</Link>
                  </Button>
                </nav>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </header>

      <SearchModal open={searchModalOpen} onOpenChange={setSearchModalOpen} />
    </>
  );
}
