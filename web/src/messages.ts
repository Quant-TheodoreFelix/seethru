import type { Lang } from "./lang";
import type { BucketVisibility, Confidence, EdgeKind, Exposure, NodeKind, PolicyCommand, ScanReport, SecretKind, Severity, Zone } from "./model";
import type { Theme } from "./theme";

export type ComponentLabel =
  | "browserCode"
  | "serverCode"
  | "edgeFunction"
  | "code"
  | "mobileCode"
  | "nativeCode"
  | "firmware"
  | "databaseCode"
  | "buildScript"
  | "migration"
  | "envFile"
  | "buildOutput"
  | "serverBuildOutput"
  | "buildCache"
  | "binary"
  | "file";

export interface Messages {
  severity: Record<Severity, string>;
  confidence: Record<Confidence, string>;
  zone: Record<Zone, string>;
  component: Record<ComponentLabel, string>;
  command: Record<PolicyCommand, string>;
  secret: Record<SecretKind, string>;
  edge: Record<EdgeKind, string>;
  theme: Record<Theme, string>;
  language: Record<Lang, string>;
  bucket: Record<BucketVisibility, string>;
  exposure: Record<Exposure, string>;
  table: string;
  view: string;
  viewCallerRights: string;
  viewOwnerRights: string;
  materialized: string;
  databaseFunction: string;
  rlsOn: string;
  rlsOff: string;
  policy: string;
  envVar: string;
  publicInBrowser: string;
  entryPoint: string;
  dataStore: string;
  accessRule: string;
  principal: string;
  config: string;
  service: string;
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
  evidence: string;
  limitations: string;
}

const LANGUAGE: Record<Lang, string> = { en: "EN", ko: "KO" };

const en: Messages = {
  severity: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" },
  confidence: { certain: "Confirmed", likely: "Likely", review: "Needs review" },
  zone: {
    client: "client",
    server: "server",
    database: "database",
    device: "device",
    buildTime: "build time",
    thirdParty: "third party",
    unknown: "unknown zone",
  },
  component: {
    browserCode: "Browser code",
    serverCode: "Server code",
    edgeFunction: "Edge Function",
    code: "Code",
    mobileCode: "Mobile code",
    nativeCode: "Native code",
    firmware: "Firmware",
    databaseCode: "Database code",
    buildScript: "Build script",
    migration: "Migration",
    envFile: "Env file",
    buildOutput: "Build output",
    serverBuildOutput: "Server build output",
    buildCache: "Build cache",
    binary: "Binary",
    file: "File",
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
    imports: "imports",
    calls: "calls",
    builtFrom: "built from",
    invokes: "invokes",
    reads: "reads",
    writes: "writes",
    usesConfig: "uses config",
    defines: "defines",
    guardedBy: "guarded by",
    actsAs: "acts as",
    appliesTo: "applies to",
    contains: "contains",
    unlocks: "unlocks",
    connectsTo: "connects to",
  },
  theme: { light: "Light", dark: "Dark" },
  language: LANGUAGE,
  bucket: { public: "Bucket · public", private: "Bucket · private", unknown: "Bucket · visibility unknown" },
  exposure: { public: "anyone can call", authenticated: "signed-in users only", internal: "internal only", unknown: "access unknown" },
  table: "Table",
  view: "View",
  viewCallerRights: "uses the caller's permissions",
  viewOwnerRights: "uses the owner's permissions",
  materialized: "materialized",
  databaseFunction: "Database function",
  rlsOn: "RLS on",
  rlsOff: "RLS off",
  policy: "Policy",
  envVar: "Env variable",
  publicInBrowser: "public in browser",
  entryPoint: "Entry point",
  dataStore: "Data store",
  accessRule: "Access rule",
  principal: "Principal",
  config: "Config",
  service: "Service",
  scanned: ({ filesScanned, filesExcluded, truncated, configFile, inputs }) =>
    [
      `${filesScanned} ${filesScanned === 1 ? "file" : "files"} scanned`,
      filesExcluded > 0 ? `${filesExcluded} excluded by ${configFile ?? "seethru.toml"}` : "",
      ...inputs.flatMap((input) => (input.type === "buildOutput" ? [`build output read from ${input.path}`] : [])),
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
  evidence: "How it gets there",
  limitations: "Not checked",
};

const ko: Messages = {
  severity: { critical: "치명적", high: "높음", medium: "중간", low: "낮음", info: "정보" },
  confidence: { certain: "확인됨", likely: "추정", review: "확인 필요" },
  zone: {
    client: "클라이언트",
    server: "서버",
    database: "데이터베이스",
    device: "기기",
    buildTime: "빌드 시점",
    thirdParty: "바깥 서비스",
    unknown: "구역 모름",
  },
  component: {
    browserCode: "브라우저 코드",
    serverCode: "서버 코드",
    edgeFunction: "Edge Function",
    code: "코드",
    mobileCode: "모바일 코드",
    nativeCode: "네이티브 코드",
    firmware: "펌웨어",
    databaseCode: "DB 코드",
    buildScript: "빌드 스크립트",
    migration: "DB 마이그레이션",
    envFile: "환경변수 파일",
    buildOutput: "빌드 결과물",
    serverBuildOutput: "서버 빌드 결과물",
    buildCache: "빌드 캐시",
    binary: "바이너리",
    file: "파일",
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
    imports: "가져옴",
    calls: "호출",
    builtFrom: "빌드 원본",
    invokes: "실행",
    reads: "조회",
    writes: "쓰기",
    usesConfig: "참조",
    defines: "정의",
    guardedBy: "정책 적용",
    actsAs: "권한으로 동작",
    appliesTo: "적용 대상",
    contains: "포함",
    unlocks: "권한 획득",
    connectsTo: "연결",
  },
  theme: { light: "라이트", dark: "다크" },
  language: LANGUAGE,
  bucket: { public: "버킷 · 공개", private: "버킷 · 비공개", unknown: "버킷 · 공개 여부 모름" },
  exposure: { public: "누구나 호출", authenticated: "로그인한 사용자만", internal: "내부 전용", unknown: "접근 범위 모름" },
  table: "테이블",
  view: "뷰",
  viewCallerRights: "호출한 사람의 권한으로 동작",
  viewOwnerRights: "만든 사람의 권한으로 동작",
  materialized: "저장형",
  databaseFunction: "DB 함수",
  rlsOn: "RLS 켜짐",
  rlsOff: "RLS 꺼짐",
  policy: "정책",
  envVar: "환경변수",
  publicInBrowser: "브라우저에 공개",
  entryPoint: "진입점",
  dataStore: "데이터 저장소",
  accessRule: "접근 규칙",
  principal: "권한 주체",
  config: "설정",
  service: "바깥 서비스",
  scanned: ({ filesScanned, filesExcluded, truncated, configFile, inputs }) =>
    [
      `파일 ${filesScanned}개 검사`,
      filesExcluded > 0 ? `${configFile ?? "seethru.toml"}로 ${filesExcluded}개 제외` : "",
      ...inputs.flatMap((input) => (input.type === "buildOutput" ? [`${input.path} 빌드 결과물 읽음`] : [])),
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
  evidence: "어떻게 닿는지",
  limitations: "확인하지 못한 것",
};

export const MESSAGES: Record<Lang, Messages> = { en, ko };

function componentLabel(kind: Extract<NodeKind, { type: "component" }>): ComponentLabel {
  switch (kind.artifact) {
    case "migration":
      return "migration";
    case "config":
      return "envFile";
    case "buildOutput":
      return kind.runtime === "server" ? "serverBuildOutput" : kind.runtime === "build" ? "buildCache" : "buildOutput";
    case "binary":
      return "binary";
    case "other":
      return "file";
    case "source":
      switch (kind.runtime) {
        case "browser":
          return "browserCode";
        case "server":
          return "serverCode";
        case "edge":
          return "edgeFunction";
        case "mobile":
          return "mobileCode";
        case "native":
          return "nativeCode";
        case "firmware":
          return "firmware";
        case "database":
          return "databaseCode";
        case "build":
          return "buildScript";
        case "unknown":
          return "code";
      }
  }
}

export function kindLabel(kind: NodeKind, m: Messages): string {
  switch (kind.type) {
    case "component":
      return m.component[componentLabel(kind)];
    case "entryPoint": {
      const base = kind.channel === "rpc" ? m.databaseFunction : m.entryPoint;
      const exposure = kind.channel === "rpc" ? m.exposure[kind.exposure] : "";
      return exposure ? `${base} · ${exposure}` : base;
    }
    case "dataStore": {
      const detail = kind.detail;
      if (detail?.type === "postgresView") {
        const rights = detail.securityInvoker && !detail.materialized ? m.viewCallerRights : m.viewOwnerRights;
        return [m.view, detail.materialized ? m.materialized : "", rights].filter(Boolean).join(" · ");
      }
      if (detail?.type === "storageBucket") return m.bucket[detail.visibility];
      const rls = detail?.type === "postgresTable" ? detail.rls : undefined;
      return rls === "enabled" ? `${m.table} · ${m.rlsOn}` : rls === "disabled" ? `${m.table} · ${m.rlsOff}` : kind.detail ? m.table : m.dataStore;
    }
    case "accessRule":
      return kind.detail ? `${m.policy} · ${m.command[kind.detail.command]} · ${kind.detail.roles.join(", ")}` : m.accessRule;
    case "principal":
      return m.principal;
    case "credential":
      return `${m.secret[kind.detail.secretKind]} · ${kind.detail.masked}`;
    case "config":
      return kind.detail ? (kind.detail.exposedToClient ? `${m.envVar} · ${m.publicInBrowser}` : m.envVar) : m.config;
    case "service":
      return m.service;
  }
}
