import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { TSchema } from "typebox";
import schema from "./verdict.schema.json";

const MAX_INVALID = 3;

export default function (pi: ExtensionAPI) {
  let submitted = false;
  let invalid = 0;
  pi.on("agent_start", () => { submitted = false; invalid = 0; });
  pi.on("session_start", () => { pi.setActiveTools(["submit_verdict"]); });
  // An invalid call returns pi's validation message (which field, what is wrong) so the
  // model can resubmit in the same session; after MAX_INVALID the Python runner retries.
  pi.on("tool_execution_end", (event, ctx) => {
    if (event.isError && (submitted || ++invalid >= MAX_INVALID)) ctx.abort();
  });
  pi.registerTool({
    name: "submit_verdict",
    label: "Submit verdict",
    description: "Submit your final security-review verdict by calling this tool exactly once. Supply arguments according to its schema and omit optional fields that do not apply. If an argument is invalid, the tool reports which field is wrong; fix it and call the tool again. The tool records your verdict and ends the evaluation. A text response does not submit a verdict. This tool does not inspect or execute code.",
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
