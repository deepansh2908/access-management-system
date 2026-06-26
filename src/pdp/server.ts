import { seed } from "../data/seed.js";
import { PORTS } from "../shared/config.js";
import { createPdpApp } from "./app.js";

createPdpApp(seed()).listen(PORTS.pdp, () =>
  console.log(`[pdp] listening on ${PORTS.pdp}`),
);
