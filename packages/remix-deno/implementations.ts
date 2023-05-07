import {
  createCookieFactory,
  createCookieSessionStorageFactory,
  createMemorySessionStorageFactory,
  createSessionStorageFactory,
} from "@remix-run/server-runtime";

export const createCookie = createCookieFactory();
export const createCookieSessionStorage = createCookieSessionStorageFactory(
  createCookie,
);
export const createSessionStorage = createSessionStorageFactory(createCookie);
export const createMemorySessionStorage = createMemorySessionStorageFactory(
  createSessionStorage,
);
