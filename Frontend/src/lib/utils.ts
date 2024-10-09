import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatPrice(price: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(price);
}

export function generateEAN8SKUFromID(id: number): string {
  const idString = id.toString().padStart(7, "0");

  const checksum = calculateEAN8Checksum(idString);

  return `${idString}${checksum}`;
}

function calculateEAN8Checksum(skuBase: string): number {
  const digits = skuBase.split("").map(Number);

  const sum = digits[0] * 3 + digits[1] + digits[2] * 3 + digits[3] + digits[4] * 3 + digits[5] + digits[6] * 3;

  const checksum = (10 - (sum % 10)) % 10;
  return checksum;
}
