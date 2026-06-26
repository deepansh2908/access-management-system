import { PORTS } from "../shared/config.js";
import { createGatewayApp } from "./app.js";

createGatewayApp().listen(PORTS.gateway, () =>
  console.log(`[gateway] listening on ${PORTS.gateway}`),
);
