import type { Lang } from "./lang";
import type { EdgeKind, FileRole, NodeKind, PolicyCommand, ScanReport, SecretKind, Severity } from "./model";
import type { Theme } from "./theme";

export interface Messages {
  severity: Record<Severity, string>;
  fileRole: Record<FileRole, string>;
  command: Record<PolicyCommand, string>;
  secret: Record<SecretKind, string>;
  edge: Record<EdgeKind, string>;
  theme: Record<Theme, string>;
  language: Record<Lang, string>;
  table: string;
  rlsOn: string;
  rlsOff: string;
  policy: string;
  envVar: string;
  publicInBrowser: string;
  scanned: (target: ScanReport["target"]) => string;
  colorTheme: string;
  languageSwitch: string;
  openTitle: string;
  openBody: string;
  openButton: string;
  readError: (detail: string) => string;
  layoutError: (detail: string) => string;
  findings: string;
  noProblems: string;
  lineStyles: string;
  selectedFinding: string;
  close: string;
  fixTitle: string;
  fixHint: string;
  fixPrompt: string;
  copy: string;
  copied: string;
  copyBlocked: string;
  acceptedTitle: string;
  acceptedNote: (config: string) => string;
  acceptedLabel: string;
  reason: string;
  findingId: string;
}

const LANGUAGE: Record<Lang, string> = { en: "EN", ko: "KO" };

const en: Messages = {
  severity: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" },
  fileRole: {
    browserCode: "Browser code",
    serverCode: "Server code",
    edgeFunction: "Edge Function",
    unknownCode: "Code",
    migration: "Migration",
    envFile: "Env file",
    buildOutput: "Build output",
    other: "File",
  },
  command: { all: "All", select: "Select", insert: "Insert", update: "Update", delete: "Delete" },
  secret: {
    supabaseServiceRoleKey: "Supabase service_role key",
    supabaseSecretKey: "Supabase secret key",
    databaseUrl: "Database URL",
    stripeSecretKey: "Stripe secret key",
    openAiApiKey: "OpenAI API key",
    anthropicApiKey: "Anthropic API key",
    awsAccessKeyId: "AWS access key",
    githubToken: "GitHub token",
    privateKey: "Private key",
  },
  edge: {
    defines: "defines",
    guardedBy: "guarded by",
    queries: "queries",
    writes: "writes",
    reads: "reads",
    contains: "contains",
  },
  theme: { light: "Light", dark: "Dark" },
  language: LANGUAGE,
  table: "Table",
  rlsOn: "RLS on",
  rlsOff: "RLS off",
  policy: "Policy",
  envVar: "Env variable",
  publicInBrowser: "public in browser",
  scanned: ({ filesScanned, filesExcluded, truncated, configFile }) =>
    [
      `${filesScanned} ${filesScanned === 1 ? "file" : "files"} scanned`,
      filesExcluded > 0 ? `${filesExcluded} excluded by ${configFile ?? "seethru.toml"}` : "",
      truncated ? "stopped early" : "",
    ]
      .filter(Boolean)
      .join(", "),
  colorTheme: "Color theme",
  languageSwitch: "Language",
  openTitle: "Open a scan report",
  openBody: "Choose a file made with `seethru scan --json`. It stays on this computer.",
  openButton: "Open report file",
  readError: (detail) => `Could not read the report file (${detail})`,
  layoutError: (detail) => `Could not draw the graph (${detail})`,
  findings: "Findings",
  noProblems: "No problems found.",
  lineStyles: "Line styles",
  selectedFinding: "Selected finding",
  close: "Close",
  fixTitle: "Ask your AI to fix it",
  fixHint: "Paste it as is into an AI coding tool such as Cursor, Claude or Lovable.",
  fixPrompt: "Fix prompt",
  copy: "Copy prompt",
  copied: "Copied",
  copyBlocked: "The browser blocked copying. The prompt is selected, so copy it yourself.",
  acceptedTitle: "Accepted",
  acceptedNote: (config) => `Marked as intended in ${config}. They do not count toward the totals above.`,
  acceptedLabel: "Accepted",
  reason: "Reason:",
  findingId: "Finding ID",
};

const ko: Messages = {
  severity: { critical: "치명적", high: "높음", medium: "중간", low: "낮음", info: "정보" },
  fileRole: {
    browserCode: "브라우저 코드",
    serverCode: "서버 코드",
    edgeFunction: "Edge Function",
    unknownCode: "코드",
    migration: "DB 마이그레이션",
    envFile: "환경변수 파일",
    buildOutput: "빌드 결과물",
    other: "파일",
  },
  command: { all: "모든 작업", select: "읽기", insert: "추가", update: "수정", delete: "삭제" },
  secret: {
    supabaseServiceRoleKey: "Supabase service_role 키",
    supabaseSecretKey: "Supabase 비밀 키",
    databaseUrl: "DB 접속 주소",
    stripeSecretKey: "Stripe 비밀 키",
    openAiApiKey: "OpenAI API 키",
    anthropicApiKey: "Anthropic API 키",
    awsAccessKeyId: "AWS 액세스 키",
    githubToken: "GitHub 토큰",
    privateKey: "개인 키",
  },
  edge: {
    defines: "정의",
    guardedBy: "정책 적용",
    queries: "조회",
    writes: "쓰기",
    reads: "참조",
    contains: "포함",
  },
  theme: { light: "라이트", dark: "다크" },
  language: LANGUAGE,
  table: "테이블",
  rlsOn: "RLS 켜짐",
  rlsOff: "RLS 꺼짐",
  policy: "정책",
  envVar: "환경변수",
  publicInBrowser: "브라우저에 공개",
  scanned: ({ filesScanned, filesExcluded, truncated, configFile }) =>
    [
      `파일 ${filesScanned}개 검사`,
      filesExcluded > 0 ? `${configFile ?? "seethru.toml"}로 ${filesExcluded}개 제외` : "",
      truncated ? "일부만 검사함" : "",
    ]
      .filter(Boolean)
      .join(", "),
  colorTheme: "색 테마",
  languageSwitch: "언어",
  openTitle: "스캔 리포트 열기",
  openBody: "`seethru scan --json`으로 만든 파일을 골라 주세요. 파일은 이 컴퓨터 밖으로 나가지 않아요.",
  openButton: "리포트 파일 열기",
  readError: (detail) => `리포트 파일을 읽지 못했어요 (${detail})`,
  layoutError: (detail) => `그래프를 그리지 못했어요 (${detail})`,
  findings: "발견한 문제",
  noProblems: "발견한 문제가 없어요.",
  lineStyles: "선 종류",
  selectedFinding: "선택한 문제",
  close: "닫기",
  fixTitle: "AI에게 고쳐 달라고 하기",
  fixHint: "Cursor, Claude, Lovable 같은 AI 코딩 도구에 그대로 붙여 넣으세요.",
  fixPrompt: "수정 프롬프트",
  copy: "프롬프트 복사",
  copied: "복사했어요",
  copyBlocked: "브라우저가 자동 복사를 막았어요. 프롬프트를 선택해 두었으니 직접 복사해 주세요.",
  acceptedTitle: "허용한 문제",
  acceptedNote: (config) => `${config}에서 의도한 것으로 표시했어요. 위 개수에는 들어가지 않아요.`,
  acceptedLabel: "허용함",
  reason: "사유:",
  findingId: "문제 ID",
};

export const MESSAGES: Record<Lang, Messages> = { en, ko };

export function kindLabel(kind: NodeKind, m: Messages): string {
  switch (kind.type) {
    case "file":
      return m.fileRole[kind.role];
    case "table":
      return kind.rls === "enabled" ? `${m.table} · ${m.rlsOn}` : kind.rls === "disabled" ? `${m.table} · ${m.rlsOff}` : m.table;
    case "policy":
      return `${m.policy} · ${m.command[kind.command]} · ${kind.roles.join(", ")}`;
    case "envVar":
      return kind.exposedToBrowser ? `${m.envVar} · ${m.publicInBrowser}` : m.envVar;
    case "secret":
      return `${m.secret[kind.secretKind]} · ${kind.masked}`;
  }
}
