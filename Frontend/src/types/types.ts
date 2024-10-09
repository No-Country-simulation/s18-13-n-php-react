export interface Product {
  id: number;
  description: string;
  link: string;
  product_picture: string;
  price: number;
  origin: string;
  batch_number: string;
  expiration_date: string;
  stock: number;
  is_featured: boolean;
}

export interface StoreState {
  isDarkMode: boolean;
  toggleDarkMode: () => void;
}

export interface LayoutProps {
  children: React.ReactNode;
}

export interface SearchModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}
