export function createFileRoute(_path: string) {
  return <T extends Record<string, unknown>>(options: T) => options;
}

export function notFound() {
  return { isNotFound: true };
}

export function Link() {
  return null;
}

export function Outlet() {
  return null;
}

export function createRootRoute() {
  return (options: Record<string, unknown>) => options;
}

export function createRouter() {
  return {};
}

export function lazyRouteComponent() {
  return null;
}
