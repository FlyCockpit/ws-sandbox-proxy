import { createServerFn } from "@tanstack/react-start";
export const getRawMcpSearch = createServerFn({ method: "GET" }).handler(
  async (): Promise<string> => {
    const { getRequestUrl } = await import("@tanstack/react-start/server");
    return new URL(getRequestUrl()).search;
  },
);
