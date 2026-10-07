import {
  defineRailway,
  github,
  preserve,
  project,
  service,
} from "railway/iac";

export const partial = "huntsman-recon";

export default defineRailway(() => {
  const app = service("huntsman-recon", {
    source: github(
      "EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-",
      { branch: "main" },
    ),
    healthcheck: "/api/health",
    healthcheckTimeout: 60,
    replicas: 1,
    env: {
      HOME: "/data",
      HUNTSMAN_DATA_DIR: "/data",
      HUNTSMAN_STARTUP_CHECK: "1",
      HSE_AUTH_TOKEN: preserve(),
    },
  });

  return project("huntsman-rust-production", {
    resources: [app],
  });
});
