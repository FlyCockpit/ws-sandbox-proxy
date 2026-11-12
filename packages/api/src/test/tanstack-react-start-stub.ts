export function createServerFn() {
  return {
    handler: <T extends (...args: never[]) => unknown>(fn: T) => fn,
  };
}

export function createClientOnlyFn<T extends (...args: never[]) => unknown>(fn: T) {
  return fn;
}

export function createServerOnlyFn<T extends (...args: never[]) => unknown>(fn: T) {
  return fn;
}

export function createIsomorphicFn() {
  return {
    server: <T extends (...args: never[]) => unknown>(fn: T) => fn,
    client: <T extends (...args: never[]) => unknown>(fn: T) => fn,
  };
}

export function createMiddleware() {
  return {
    server: <T extends (...args: never[]) => unknown>(fn: T) => fn,
  };
}

export function createCsrfMiddleware() {
  return {};
}

export function createStart() {
  return {};
}

export function useServerFn<T extends (...args: never[]) => unknown>(fn: T) {
  return fn;
}
