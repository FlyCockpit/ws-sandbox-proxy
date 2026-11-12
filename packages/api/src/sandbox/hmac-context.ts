/**
 * LP(x) = u32be(UTF8-byte-length(x)) || UTF8(x). Each domain/version, key ID,
 * server/owner/host binding, principal marker and canonical payload is a separate
 * field.
 */
export function encodeHmacContext(fields: readonly string[]): Buffer {
  return Buffer.concat(
    fields.map((field) => {
      const bytes = Buffer.from(field, "utf8");
      const length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.byteLength);
      return Buffer.concat([length, bytes]);
    }),
  );
}
