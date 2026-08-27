export {
  AuditCell,
  CapabilityGenerationCell,
  ExtensionStateCell,
  SessionCell,
  UserCell,
  WorkspaceCell,
} from "./cells.ts";

import { handleStateIngress } from "./ingress.ts";

export default {
  fetch: handleStateIngress,
};
