import type { ReplayPolicy } from "@circulusd/protocol-types";

/**
 * Tools exposed to the agent. In circulusd proper these are dispatched
 * through the executor/MCP effect services behind a dispatch permit; here the
 * base tools run in-process, and `python` goes through circulusd's sandboxd
 * (see python-tool.ts and sandbox/executor.ts).
 */
export interface ToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly parameters: Readonly<Record<string, unknown>>;
  readonly replayPolicy: ReplayPolicy;
  /** A plain string is a successful result; return a ToolExecution to flag an error explicitly. */
  run(
    args: Readonly<Record<string, unknown>>,
    context: ToolContext,
  ): Promise<string | ToolExecution> | string | ToolExecution;
}

/** Identity of the effect dispatch a tool call belongs to (the engine's request plus session/turn ids). */
export interface ToolContext {
  readonly sessionId: string;
  readonly turnId: string;
  readonly toolCallId: string;
  /** Fires when the turn is aborted; long-running tools stop their work on it. */
  readonly signal: AbortSignal;
  readonly effect: {
    /** The engine's effect request digest (`sha256:<hex>`). */
    readonly requestDigest: string;
    readonly replayPolicy: ReplayPolicy;
    readonly operation: string;
  };
}

export interface ToolExecution {
  readonly text: string;
  readonly isError: boolean;
}

export const BASE_TOOL_DEFINITIONS: readonly ToolDefinition[] = [
  {
    name: "echo",
    description: "Repeat the given text back verbatim.",
    parameters: {
      type: "object",
      properties: { text: { type: "string", description: "Text to repeat" } },
      required: ["text"],
      additionalProperties: false,
    },
    replayPolicy: "safe",
    run: (args) => String(args.text ?? ""),
  },
  {
    name: "now",
    description: "Return the current date and time of the backend host.",
    parameters: { type: "object", properties: {}, additionalProperties: false },
    replayPolicy: "safe",
    run: () => {
      const now = new Date();
      return `${now.toISOString()} (local: ${now.toString()})`;
    },
  },
  {
    name: "calculator",
    description:
      "Evaluate an arithmetic expression using + - * / % ^ and parentheses. Returns the numeric result.",
    parameters: {
      type: "object",
      properties: {
        expression: { type: "string", description: "Arithmetic expression, e.g. 12*(3+4)" },
      },
      required: ["expression"],
      additionalProperties: false,
    },
    replayPolicy: "safe",
    run: (args) => String(evaluateArithmetic(String(args.expression ?? ""))),
  },
];

/** The base tools plus whatever optional tools (python) the process could set up. */
export function createToolDefinitions(extra: readonly ToolDefinition[]): readonly ToolDefinition[] {
  return [...BASE_TOOL_DEFINITIONS, ...extra];
}

export function findTool(tools: readonly ToolDefinition[], name: string): ToolDefinition | undefined {
  return tools.find((tool) => tool.name === name);
}

export async function executeTool(
  tools: readonly ToolDefinition[],
  name: string,
  args: Readonly<Record<string, unknown>>,
  context: ToolContext,
): Promise<ToolExecution> {
  const tool = findTool(tools, name);
  if (tool === undefined) {
    return { text: `unknown tool: ${name}`, isError: true };
  }
  try {
    const result = await tool.run(args, context);
    return typeof result === "string" ? { text: result, isError: false } : result;
  } catch (error) {
    return { text: error instanceof Error ? error.message : String(error), isError: true };
  }
}

/** Small recursive-descent evaluator; never uses eval. */
export function evaluateArithmetic(expression: string): number {
  const source = expression.replace(/\s+/g, "");
  if (source.length === 0 || source.length > 256) {
    throw new Error("expression must be 1..256 non-blank characters");
  }
  let index = 0;
  const peek = (): string => source[index] ?? "";

  const parseNumber = (): number => {
    const match = /^\d+(?:\.\d+)?/.exec(source.slice(index));
    if (match === null) {
      throw new Error(`unexpected token at ${index}: ${peek() === "" ? "end of input" : peek()}`);
    }
    index += match[0].length;
    return Number(match[0]);
  };
  const parsePrimary = (): number => {
    if (peek() === "(") {
      index += 1;
      const value = parseExpression();
      if (peek() !== ")") throw new Error("missing closing parenthesis");
      index += 1;
      return value;
    }
    return parseNumber();
  };
  // `^` binds tighter than a unary sign (so -2^2 is -4, as in Python and
  // mathematics) and is right-associative (2^3^2 is 2^9).
  const parsePower = (): number => {
    const base = parsePrimary();
    if (peek() === "^") {
      index += 1;
      return base ** parseUnary();
    }
    return base;
  };
  const parseUnary = (): number => {
    if (peek() === "-") {
      index += 1;
      return -parseUnary();
    }
    if (peek() === "+") {
      index += 1;
      return parseUnary();
    }
    return parsePower();
  };
  const parseTerm = (): number => {
    let value = parseUnary();
    while (peek() === "*" || peek() === "/" || peek() === "%") {
      const operator = source[index];
      index += 1;
      const right = parseUnary();
      if (operator === "*") value *= right;
      else if (operator === "/") {
        if (right === 0) throw new Error("division by zero");
        value /= right;
      } else value %= right;
    }
    return value;
  };
  const parseExpression = (): number => {
    let value = parseTerm();
    while (peek() === "+" || peek() === "-") {
      const operator = source[index];
      index += 1;
      const right = parseTerm();
      value = operator === "+" ? value + right : value - right;
    }
    return value;
  };

  const result = parseExpression();
  if (index !== source.length) {
    throw new Error(`unexpected token at ${index}: ${peek()}`);
  }
  if (!Number.isFinite(result)) {
    throw new Error("result is not a finite number");
  }
  return result;
}
