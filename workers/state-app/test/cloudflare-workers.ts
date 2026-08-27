export class DurableObject<Environment = unknown> {
  protected readonly ctx: unknown;
  protected readonly env: Environment;

  constructor(ctx: unknown, env: Environment) {
    this.ctx = ctx;
    this.env = env;
  }
}
