import { PORTS } from "../../shared/config.js";
import { seededExpenseRepository } from "../../data/expense-store.js";
import { createExpenseApp } from "./app.js";

createExpenseApp(seededExpenseRepository()).listen(PORTS.expense, () =>
  console.log(`[expense] listening on ${PORTS.expense}`),
);
