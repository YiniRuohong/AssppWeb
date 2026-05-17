export class AuthenticationError extends Error {
  public readonly codeRequired: boolean;
  public readonly kind?: string;

  constructor(
    message: string,
    options?: { codeRequired?: boolean; kind?: string },
  ) {
    super(message);
    this.name = "AuthenticationError";
    this.codeRequired = options?.codeRequired ?? false;
    this.kind = options?.kind;
  }
}
