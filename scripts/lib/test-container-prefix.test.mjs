import assert from "node:assert/strict";
import { test } from "node:test";

import { testContainerPrefix } from "./test-container-prefix.mjs";

test("the flag wins, then TEST_CONTAINER_PREFIX, then the default", () => {
  assert.equal(testContainerPrefix({ env: {} }), "wssp");
  assert.equal(
    testContainerPrefix({ env: {}, fallback: "wssp-test-migrations" }),
    "wssp-test-migrations",
  );
  assert.equal(
    testContainerPrefix({ env: { TEST_CONTAINER_PREFIX: "rp5-52a-wssp" } }),
    "rp5-52a-wssp",
  );
  assert.equal(
    testContainerPrefix({
      argv: ["--container-prefix", "rp5-flag"],
      env: { TEST_CONTAINER_PREFIX: "rp5-env" },
    }),
    "rp5-flag",
  );
});

test("an empty or invalid prefix is an error, never the default", () => {
  for (const bad of ["", "Bad", "a-", "a..b", "x".repeat(25)])
    assert.throws(
      () => testContainerPrefix({ env: { TEST_CONTAINER_PREFIX: bad } }),
      /TEST_CONTAINER_PREFIX needs a Docker name prefix/,
      bad,
    );
  assert.throws(
    () => testContainerPrefix({ argv: ["--container-prefix"], env: {} }),
    /--container-prefix needs a Docker name prefix/,
  );
});
