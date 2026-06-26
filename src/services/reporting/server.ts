import { PORTS } from "../../shared/config.js";
import { createReportingApp } from "./app.js";

createReportingApp().listen(PORTS.reporting, () =>
  console.log(`[reporting] listening on ${PORTS.reporting}`),
);
