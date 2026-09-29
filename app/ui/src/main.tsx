import { createRoot } from "react-dom/client";
import { App } from "./App";
import { AppCrash, ErrorBoundary } from "./components/ErrorBoundary";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <ErrorBoundary name="app" fallback={(e) => <AppCrash error={e} />}>
    <App />
  </ErrorBoundary>,
);
