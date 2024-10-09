import { Link } from "react-router-dom";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

const roles = [
  {
    title: "Admin",
    description: "Gestiona el sistema y los usuarios.",
    link: "/admin/dashboard",
    ariaLabel: "Ingresar como Administrador",
  },
  {
    title: "Cliente",
    description: "Accede a tu cuenta y gestiona tus pedidos.",
    link: "/client/dashboard",
    ariaLabel: "Ingresar como Cliente",
  },
  {
    title: "Productor",
    description: "Gestiona tus productos y ventas.",
    link: "/producer/dashboard",
    ariaLabel: "Ingresar como Productor",
  },
];

export default function AdminDashboard() {
  return (
    <div className="min-h-screen p-8 text-center max-w-7xl mx-auto">
      <h1 className="text-4xl font-bold mb-6">Bienvenido a Raices Orgánicas</h1>
      <p className="p-6">La mejor tienda de productos 100% orgánicos</p>
      <h2 className="pb-4 font-semibold">Elige un rol para continuar:</h2>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {roles.map((role) => (
          <Card key={role.title}>
            <CardHeader>
              <CardTitle className="text-xl font-semibold">{role.title}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="mb-4">{role.description}</p>
              <Link to={role.link}>
                <Button aria-label={role.ariaLabel} className="w-full">
                  Ingresar como {role.title}
                </Button>
              </Link>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
