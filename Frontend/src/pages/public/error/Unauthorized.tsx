import { LockIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "@/components/ui/card";
import { Link } from "react-router-dom";

export default function Unauthorized() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-background">
      <Card className="w-[420px] text-center">
        <CardHeader>
          <div className="flex justify-center mb-4">
            <LockIcon className="h-12 w-12 text-destructive" />
          </div>
          <CardTitle className="text-3xl font-bold">403</CardTitle>
          <CardDescription className="text-xl">Acceso no autorizado</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">
            Lo sentimos, no tienes permiso para acceder a esta página. Si crees que esto es un error, por favor contacta al administrador del sitio.
          </p>
        </CardContent>
        <CardFooter className="flex justify-center gap-4">
          <Button asChild variant="outline">
            <Link to="/">Volver al inicio</Link>
          </Button>
          <Button asChild>
            <Link to="/login">Iniciar sesión</Link>
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}
