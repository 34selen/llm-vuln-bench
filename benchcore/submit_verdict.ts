import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { TSchema } from "typebox";
import schema from "./verdict.schema.json";

const MAX_INVALID = 3;

export default function (pi: ExtensionAPI) {
  let submitted = false;
  let invalid = 0;
  let gates: Record<string, Array<Array<[number, boolean]>>> | null = null;

  const loadGates = (): Record<string, Array<Array<[number, boolean]>>> | null => {
    if (gates !== null) return gates;
    const path = process.env.BENCH_GATE_FILE;
    if (!path) return null;
    try {
      gates = JSON.parse(require("fs").readFileSync(path, "utf8"));
    } catch {
      gates = null;
    }
    return gates;
  };

  pi.on("agent_start", () => { submitted = false; invalid = 0; });
  pi.on("session_start", () => {
    // check_assignment exists only for runs that provide gate data; keeping
    // it out of the active set otherwise stops plain verdict runs from
    // ever seeing (and erroring on) it.
    const withCheck = process.env.BENCH_GATE_FILE ? ["submit_verdict", "check_assignment"] : ["submit_verdict"];
    pi.setActiveTools(withCheck);
  });
  // An invalid call returns pi's validation message (which field, what is wrong) so the
  // model can resubmit in the same session; after MAX_INVALID the Python runner retries.
  pi.on("tool_execution_end", (event, ctx) => {
    if (event.isError && event.toolName === "submit_verdict"
        && (submitted || ++invalid >= MAX_INVALID)) ctx.abort();
  });

  pi.registerTool({
    name: "check_assignment",
    label: "Check a gate assignment",
    description: "Evaluate a complete flag-bit assignment against every policy clause of the code under review. Provide the assignment as a hex token (the same string the program would take as its flags argument; bits past the token's end read as 0). Returns, per policy, whether it holds and which clauses the assignment violates. Use it to check any candidate token before drawing conclusions about satisfiability. Note: an assignment that violates clauses does NOT establish unsatisfiability — only a failed search over assignments would; a different token may satisfy everything.",
    parameters: {
      type: "object",
      additionalProperties: false,
      required: ["token"],
      properties: {
        token: { type: "string", pattern: "^[0-9a-fA-F]{1,64}$",
                 description: "Hex flag token encoding the full bit assignment" },
      },
    } as unknown as TSchema,
    async execute(_toolCallId: number, params: { token: string }) {
      const g = loadGates();
      if (!g || Object.keys(g).length === 0) {
        throw new Error("no gate data for this case");
      }
      const tok = params.token.toLowerCase();
      const bit = (i: number): boolean => {
        const pos = Math.floor(i / 4);
        if (pos >= tok.length) return false;
        return ((parseInt(tok[pos], 16) >> (i % 4)) & 1) === 1;
      };
      const lines: string[] = [];
      let all = true;
      const render = (cl: Array<[number, boolean]>): string =>
        "(" + cl.map(([v, neg]: [number, boolean]) => (neg ? "!" : "") + `f[${v}]`).join(" || ") + ")";
      for (const name of Object.keys(g).sort()) {
        const bad: string[] = [];
        let n = 0;
        for (const cl of g[name]) {
          if (!cl.some(([v, neg]: [number, boolean]) => bit(v) !== neg)) {
            n++;
            if (bad.length < 3) bad.push(render(cl));
          }
        }
        if (n === 0) {
          lines.push(`${name}: HOLDS (${g[name].length} clauses all satisfied)`);
        } else {
          all = false;
          lines.push(`${name}: VIOLATED by this assignment (${n} of ${g[name].length} clauses fail), e.g. ${bad.join(", ")}`);
        }
      }
      lines.push(all
        ? "ALL POLICIES SATISFIED -- this token opens every gate."
        : "This assignment fails at least one policy. That does not establish unsatisfiability: only this particular token fails, and another may satisfy everything.");
      return { content: [{ type: "text", text: lines.join("\n") }] };
    },
  });

  pi.registerTool({
    name: "submit_verdict",
    label: "Submit verdict",
    description: "Submit your final security-review verdict by calling this tool exactly once. Supply arguments according to its schema and omit optional fields that do not apply. If an argument is invalid, the tool reports which field is wrong; fix it and call the tool again. The tool records your verdict and ends the evaluation. A text response does not submit a verdict. This tool does not inspect or execute code.",
    // Keep the JSON schema free of the loader's module interop wrappers.
    parameters: JSON.parse(JSON.stringify(schema)) as TSchema,
    async execute(_toolCallId: number, params) {
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
