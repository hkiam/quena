import { describe, expect, it } from "vitest";
import { addClause, clause, fieldOf, filtersOn } from "./columnFilter";

describe("column filters", () => {
  it("map columns to fields", () => {
    expect(fieldOf("result")).toBe("status");
    expect(fieldOf("remoteIp")).toBe("ip");
    expect(fieldOf("caching")).toBeNull();
    expect(fieldOf("header2", [{ response: false, name: "A" }, { response: true, name: "Server" }])).toBe("resheader.server");
    expect(fieldOf("header3", [])).toBeNull();
  });
  it("turn input into clauses", () => {
    expect(clause("status", ">= 400")).toBe("status >= 400");
    expect(clause("status", "404")).toBe("status == 404");
    expect(clause("status", "5xx")).toBe("status == 5xx");
    expect(clause("size", ">1m")).toBe("size > 1m");
    expect(clause("host", "example")).toBe('host ~ "example"');
    expect(clause("host", "*.example.com")).toBe('host ~= "*.example.com"');
    expect(clause("host", "= a.b")).toBe('host == "a.b"');
    expect(clause("path", '!~ say "hi"')).toBe('path !~ "say \\"hi\\""');
    expect(clause("resheader.server", '== ""')).toBe('resheader.server == ""');
    expect(clause("host", "  ")).toBeNull();
  });
  it("combine and recognise", () => {
    expect(addClause("", "a == 1")).toBe("a == 1");
    expect(addClause("b == 2", "a == 1")).toBe("b == 2 and a == 1");
    expect(addClause("b == 2 or c == 3", "a == 1")).toBe("(b == 2 or c == 3) and a == 1");
    expect(filtersOn('host ~ "x" and status >= 400', "status")).toBe(true);
    expect(filtersOn('hostname ~ "x"', "host")).toBe(false);
    expect(filtersOn("resheader.server == nginx", "resheader.server")).toBe(true);
  });
});
