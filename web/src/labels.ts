import type { EdgeKind, FileRole, NodeKind, PolicyCommand, SecretKind, Severity } from "./model";

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const FILE_ROLE_LABEL: Record<FileRole, string> = {
  browserCode: "Browser code",
  serverCode: "Server code",
  edgeFunction: "Edge Function",
  unknownCode: "Code",
  migration: "Migration",
  envFile: "Env file",
  buildOutput: "Build output",
  other: "File",
};

const COMMAND_LABEL: Record<PolicyCommand, string> = {
  all: "All",
  select: "Select",
  insert: "Insert",
  update: "Update",
  delete: "Delete",
};

const SECRET_LABEL: Record<SecretKind, string> = {
  supabaseServiceRoleKey: "Supabase service_role key",
  supabaseSecretKey: "Supabase secret key",
  databaseUrl: "Database URL",
  stripeSecretKey: "Stripe secret key",
  openAiApiKey: "OpenAI API key",
  anthropicApiKey: "Anthropic API key",
  awsAccessKeyId: "AWS access key",
  githubToken: "GitHub token",
  privateKey: "Private key",
};

export const EDGE_LABEL: Record<EdgeKind, string> = {
  defines: "defines",
  guardedBy: "guarded by",
  queries: "queries",
  writes: "writes",
  reads: "reads",
  contains: "contains",
};

export function kindLabel(kind: NodeKind): string {
  switch (kind.type) {
    case "file":
      return FILE_ROLE_LABEL[kind.role];
    case "table":
      return kind.rls === "enabled" ? "Table · RLS on" : kind.rls === "disabled" ? "Table · RLS off" : "Table";
    case "policy":
      return `Policy · ${COMMAND_LABEL[kind.command]} · ${kind.roles.join(", ")}`;
    case "envVar":
      return kind.exposedToBrowser ? "Env variable · public in browser" : "Env variable";
    case "secret":
      return `${SECRET_LABEL[kind.secretKind]} · ${kind.masked}`;
  }
}
