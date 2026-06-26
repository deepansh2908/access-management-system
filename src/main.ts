/**
 * Single-process orchestrator: boots all services together for easy local
 * development and testing. Auth and the PDP share one seeded store so users and
 * (dynamically edited) roles stay consistent. In production each of these is an
 * independently deployed, horizontally scaled service (see docker-compose.yml
 * for the separate-process / separate-container layout).
 */
import { seed } from "./data/seed.js";
import { seededExpenseRepository } from "./data/expense-store.js";
import { PORTS } from "./shared/config.js";
import { createAuthApp } from "./auth-service/app.js";
import { createPdpApp } from "./pdp/app.js";
import { createGatewayApp } from "./gateway/app.js";
import { createExpenseApp } from "./services/expense/app.js";
import { createReportingApp } from "./services/reporting/app.js";

const store = seed();

createAuthApp(store).listen(PORTS.auth, () => console.log(`[auth]      :${PORTS.auth}`));
createPdpApp(store).listen(PORTS.pdp, () => console.log(`[pdp]       :${PORTS.pdp}`));
createExpenseApp(seededExpenseRepository()).listen(PORTS.expense, () => console.log(`[expense]   :${PORTS.expense}`));
createReportingApp().listen(PORTS.reporting, () => console.log(`[reporting] :${PORTS.reporting}`));
createGatewayApp().listen(PORTS.gateway, () =>
  console.log(`[gateway]   :${PORTS.gateway}  <- send client requests here`),
);
