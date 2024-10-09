import { cn } from "@/lib/utils";
import { Link } from "react-router-dom";

type LogoProps = {
  size?: "sm" | "md" | "lg";
  variant?: "default" | "muted";
  className?: string;
};

export default function Logo({ size = "md", variant = "default", className }: LogoProps) {
  const sizeClasses = {
    sm: "text-lg",
    md: "text-2xl",
    lg: "text-4xl",
  };

  const variantClasses = {
    default: "text-foreground",
    muted: "text-muted-foreground",
  };

  return (
    <div className={cn("font-bold", sizeClasses[size], variantClasses[variant], className)}>
      <Link to="/" aria-label="Inicio">
        <span>Raices</span>
        <span>Orgánicas</span>
      </Link>
    </div>
  );
}
