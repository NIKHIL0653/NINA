import { useEffect, useState } from "react";

export function useDarkMode() {
  const [isDark, setIsDark] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    
    // Check localStorage first
    const stored = localStorage.getItem("theme");
    if (stored) {
      return stored === "dark";
    }
    
    // Fall back to system preference
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  });

  useEffect(() => {
    const root = document.documentElement;
    
    if (isDark) {
      root.classList.add("dark");
      root.classList.remove("light");
    } else {
      root.classList.add("light");
      root.classList.remove("dark");
    }
    
    localStorage.setItem("theme", isDark ? "dark" : "light");
  }, [isDark]);

  // Listen for system theme changes
  useEffect(() => {
    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    
    const handleChange = (e: MediaQueryListEvent) => {
      // Only update if no manual preference is stored
      if (!localStorage.getItem("theme")) {
        setIsDark(e.matches);
      }
    };
    
    mediaQuery.addEventListener("change", handleChange);
    return () => mediaQuery.removeEventListener("change", handleChange);
  }, []);

  const toggle = () => setIsDark(!isDark);
  const setDark = () => setIsDark(true);
  const setLight = () => setIsDark(false);

  return {
    isDark,
    toggle,
    setDark,
    setLight,
  };
}
