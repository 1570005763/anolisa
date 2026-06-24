import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isCapabilityEnabled } from "../../src/registration.js";
import type { SecurityCapability } from "../../src/types.js";
import { skillLedger } from "../../src/capabilities/skill-ledger.js";

function capability(id: string): SecurityCapability {
  return {
    id,
    name: id,
    hooks: [],
    register: () => {},
  };
}

describe("capability registration defaults", () => {
  it("enables capabilities by default", () => {
    assert.equal(isCapabilityEnabled(capability("scan-code"), {}), true);
  });

  it("enables skill-ledger by default", () => {
    assert.equal(isCapabilityEnabled(skillLedger, {}), true);
  });

  it("lets explicit config disable capabilities", () => {
    assert.equal(
      isCapabilityEnabled(capability("prompt-scan"), {
        "prompt-scan": { enabled: false },
      }),
      false,
    );
  });
});
