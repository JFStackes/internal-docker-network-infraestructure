# Contributing internally

Use short-lived feature/fix branches and review into main. Do not maintain central/node/customer branches. A change must include tests, updated inventory/examples when relevant, matching English/Spanish READMEs and accurate validation evidence.

Set up the virtualenv and run both commands in README.md. Never run tests against production, include real secrets in fixtures or publish operational inventories. The supplied JFStack inventory is a documented example; remove it from customer/public distributions when topology disclosure is inappropriate.

Before changing dependencies or images, consult official releases and test the relevant deployment path. CI verifies code/configuration, not a customer's firewall. Follow AGENTS.md invariants. Version changes, license changes and architecture/security boundary changes require owner review. There are no automatic release/publish/deploy workflows.
