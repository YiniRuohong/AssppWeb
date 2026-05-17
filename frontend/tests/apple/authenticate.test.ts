import { beforeEach, describe, expect, it, vi } from "vitest";
import { authenticate } from "../../src/apple/authenticate";
import { gsaAuthenticate } from "../../src/apple/gsa";

vi.mock("../../src/apple/gsa", () => ({
  gsaAuthenticate: vi.fn(),
}));

describe("apple/authenticate", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("uses GSA auth directly for sign-in", async () => {
    vi.mocked(gsaAuthenticate).mockResolvedValue({
      email: "test@example.com",
      password: "password",
      appleId: "test@example.com",
      store: "143441",
      firstName: "GSA",
      lastName: "User",
      passwordToken: "token",
      directoryServicesIdentifier: "123",
      cookies: [],
      deviceIdentifier: "aabbccddeeff",
    });

    const result = await authenticate(
      "test@example.com",
      "password",
      undefined,
      undefined,
      "aabbccddeeff",
    );

    expect(gsaAuthenticate).toHaveBeenCalledWith(
      "test@example.com",
      "password",
      "",
      "aabbccddeeff",
    );
    expect(result.firstName).toBe("GSA");
  });
});
