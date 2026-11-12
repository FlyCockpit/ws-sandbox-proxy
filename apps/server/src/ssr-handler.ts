/** Load the built renderer only when constructing the production application. */
export async function loadSsrHandler(
  url: string,
): Promise<{ fetch: (request: Request) => Promise<Response> }> {
  const { default: handler } = await import(url);
  return handler;
}
