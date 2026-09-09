// R1 spike entry (.mjs so node's entry-format check passes; the registered
// ts load hook transpiles the imported .ts body). See spike-runner-inner.ts.
await import("./spike-runner-inner.ts");
