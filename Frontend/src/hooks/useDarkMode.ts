import { useEffect } from "react";
import { themeStore } from "@/store/themeStore";

const useDarkMode = () => {
  const { isDarkMode } = themeStore();

  useEffect(() => {
    document.documentElement.classList.toggle("dark", isDarkMode);
    localStorage.setItem("darkMode", String(isDarkMode));
  }, [isDarkMode]);
};

export default useDarkMode;
