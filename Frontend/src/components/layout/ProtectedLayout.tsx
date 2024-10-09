import { SiteFooter } from "@/components/ui/site-footer";
import AuthenticatedNavbar from "../custom/AuthenticatedNavbar";
import { LayoutProps } from "@/types/types";

export default function ProtectedLayout({ children }: LayoutProps) {
  return (
    <main className="flex flex-col min-h-screen">
      <AuthenticatedNavbar />

      <main className="flex-grow p-4">{children}</main>

      <SiteFooter />
    </main>
  );
}
