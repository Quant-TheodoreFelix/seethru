import type { EdgeKind, FileRole, NodeKind, PolicyCommand, SecretKind, Severity } from "./model";

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "치명적",
  high: "높음",
  medium: "중간",
  low: "낮음",
  info: "정보",
};

const FILE_ROLE_LABEL: Record<FileRole, string> = {
  browserCode: "브라우저 코드",
  serverCode: "서버 코드",
  edgeFunction: "Edge Function",
  unknownCode: "코드",
  migration: "DB 마이그레이션",
  envFile: "환경변수 파일",
  buildOutput: "빌드 결과물",
  other: "파일",
};

const COMMAND_LABEL: Record<PolicyCommand, string> = {
  all: "모든 작업",
  select: "읽기",
  insert: "추가",
  update: "수정",
  delete: "삭제",
};

const SECRET_LABEL: Record<SecretKind, string> = {
  supabaseServiceRoleKey: "Supabase service_role 키",
  supabaseSecretKey: "Supabase 비밀 키",
  databaseUrl: "DB 접속 주소",
  stripeSecretKey: "Stripe 비밀 키",
  openAiApiKey: "OpenAI API 키",
  anthropicApiKey: "Anthropic API 키",
  awsAccessKeyId: "AWS 액세스 키",
  githubToken: "GitHub 토큰",
  privateKey: "개인 키",
};

export const EDGE_LABEL: Record<EdgeKind, string> = {
  defines: "정의",
  guardedBy: "정책",
  queries: "조회",
  reads: "참조",
  contains: "포함",
};

export function kindLabel(kind: NodeKind): string {
  switch (kind.type) {
    case "file":
      return FILE_ROLE_LABEL[kind.role];
    case "table":
      return kind.rls === "enabled" ? "테이블 · RLS 켜짐" : kind.rls === "disabled" ? "테이블 · RLS 꺼짐" : "테이블";
    case "policy":
      return `정책 · ${COMMAND_LABEL[kind.command]} · ${kind.roles.join(", ")}`;
    case "envVar":
      return kind.exposedToBrowser ? "환경변수 · 브라우저에 공개" : "환경변수";
    case "secret":
      return `${SECRET_LABEL[kind.secretKind]} · ${kind.masked}`;
  }
}
