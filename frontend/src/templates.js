// Small helpers for Lit templates.

/**
 * Lit renders arrays of templates without separators; this re-creates the
 * old `parts.join(sep)` output by interleaving a text separator.
 */
export function joinTemplates(items, separator) {
  const out = [];
  items.forEach((item, index) => {
    if (index > 0) out.push(separator);
    out.push(item);
  });
  return out.length ? out : "";
}
