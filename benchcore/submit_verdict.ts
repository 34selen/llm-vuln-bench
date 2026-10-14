import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { TSchema } from "typebox";
import schema from "./verdict.schema.json";

export default function (pi: ExtensionAPI) {
  let submitted = false;
  pi.on("agent_start", () => { submitted = false; });
  pi.on("session_start", () => { pi.setActiveTools(["submit_verdict"]); });
  // Invalid calls end this attempt; the Python runner owns the retry budget.
  pi.on("tool_execution_end", (event, ctx) => {
    if (event.isError) ctx.abort();
  });
  pi.registerTool({
    name: "submit_verdict",
    label: "Submit verdict",
    description: "Submit your final security-review verdict by calling this tool exactly once. Supply all six required arguments according to its schema. The tool records your verdict and ends the evaluation. A text response does not submit a verdict. This tool does not inspect or execute code.",
    // Keep the JSON schema free of the loader's module interop wrappers.
    parameters: JSON.parse(JSON.stringify(schema)) as TSchema,
    async execute(_toolCallId, params) {
      if (submitted) throw new Error("A verdict has already been submitted");
      submitted = true;
      return {
        content: [{ type: "text", text: "Verdict recorded." }],
        details: { verdict: params },
        terminate: true,
      };
    },
  });
}
