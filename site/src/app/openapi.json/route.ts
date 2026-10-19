import { loadOpenApi } from "@/lib/openapi";

// Written once at build time into out/openapi.json.
export const dynamic = "force-static";

export function GET(): Response {
  return new Response(JSON.stringify(loadOpenApi().raw, null, 1) + "\n", {
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}
