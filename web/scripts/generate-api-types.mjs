import { readFileSync, writeFileSync } from "node:fs";

const [input, output] = process.argv.slice(2);
if (!input || !output) throw new Error("usage: generate-api-types <openapi.json> <output.ts>");
const document = JSON.parse(readFileSync(input, "utf8"));
const schemas = document.components?.schemas ?? {};
const names = Object.keys(schemas).sort();

function typeFor(schema = {}) {
  if (schema.$ref) return schema.$ref.split("/").at(-1);
  if (schema.oneOf) return schema.oneOf.map(typeFor).join(" | ");
  if (schema.anyOf) return schema.anyOf.map(typeFor).join(" | ");
  if (schema.enum) return schema.enum.map(value => JSON.stringify(value)).join(" | ");

  const variants = Array.isArray(schema.type) ? schema.type : [schema.type];
  const rendered = variants.map(type => {
    if (type === "null") return "null";
    if (type === "string") return "string";
    if (type === "integer" || type === "number") return "number";
    if (type === "boolean") return "boolean";
    if (type === "array") return `Array<${typeFor(schema.items)}> ` .trim();
    if (type === "object" || schema.properties) {
      const required = new Set(schema.required ?? []);
      const fields = Object.entries(schema.properties ?? {}).map(([name, value]) =>
        `  ${JSON.stringify(name)}${required.has(name) ? "" : "?"}: ${typeFor(value)};`
      );
      return `{\n${fields.join("\n")}\n}`;
    }
    return "unknown";
  });
  return [...new Set(rendered)].join(" | ");
}

const declarations = names.map(name => `export type ${name} = ${typeFor(schemas[name])};`).join("\n\n");
const source = `// Generated from ../openapi.json. Do not edit.\n\n${declarations}\n\nexport type ApiSchemaName = ${names.map(name => JSON.stringify(name)).join(" | ") || "never"};\nexport const apiSchemaNames = ${JSON.stringify(names, null, 2)} as const;\n`;
writeFileSync(output, source);
