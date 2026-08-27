export const REFERENCE_HOST_PROFILE = Object.freeze({
  kind: "reference" as const,
  productionEligible: false as const,
  processLocal: true as const,
  restartPersistence: false as const,
  conformanceClaimed: false as const,
});

export const CELLD_HOST_PROFILE = Object.freeze({
  kind: "celld-v0.3-unqualified" as const,
  productionEligible: false as const,
  processLocal: false as const,
  restartPersistence: false as const,
  conformanceClaimed: false as const,
  requiresRuntimeConformance: true as const,
});
