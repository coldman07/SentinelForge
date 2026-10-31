import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: fileURLToPath(new URL("../gateway/internal/dashboard/dist", import.meta.url)),
    emptyOutDir: true,
    assetsDir: "",
  },
});
