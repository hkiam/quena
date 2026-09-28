// File menu: save bodies now; archives (SAZ/HAR) arrive with M5.
import { save } from "@tauri-apps/plugin-dialog";
import { api } from "./api";
import { get, say } from "./store";

export async function handleFileMenu(id: string): Promise<boolean> {
  switch (id) {
    case "file.save-response-body":
    case "file.save-request-body": {
      const sid = get().focusId;
      if (sid == null) return true;
      const part = id === "file.save-request-body" ? "request" : "response";
      const d = await api.detail(sid);
      if (!d) return true;
      const info = part === "request" ? d.requestBody : d.responseBody;
      const name = (d.request.url.split("?")[0].split("/").pop() || `body-${sid}`).replace(/[^\w.-]/g, "_");
      const path = await save({ defaultPath: name || `body-${sid}.bin` });
      if (!path) return true;
      const variant = get().settings?.decode && info.variants.includes("decoded") ? "decoded" : "raw";
      await api.saveBody(sid, part, variant, path);
      say(`Saving ${part} body to ${path}`);
      return true;
    }
  }
  return false;
}
