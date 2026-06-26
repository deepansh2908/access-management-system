import { seed } from "../data/seed.js";
import { PORTS } from "../shared/config.js";
import { createAuthApp } from "./app.js";

createAuthApp(seed()).listen(PORTS.auth, () =>
  console.log(`[auth] listening on ${PORTS.auth}`),
);
