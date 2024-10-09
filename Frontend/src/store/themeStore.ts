import { StoreState } from "@/types/types";
import { create } from "zustand";
import { persist } from "zustand/middleware";

export const themeStore = create(
  persist<StoreState>(
    (set) => {
      const savedMode = localStorage.getItem("darkMode") === "true";
      return {
        isDarkMode: savedMode,
        toggleDarkMode: () => set((state) => ({ isDarkMode: !state.isDarkMode })),
      };
    },
    {
      name: "settings-storage",
    },
  ),
);
