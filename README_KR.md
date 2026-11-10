# seethru

<div align="center">

**"_See through_ your app before attackers do."  
당신의 앱을 공격자보다 먼저 꿰뚫어 보세요.**

[English](README.md) | 한국어

</div>

seethru는 바이브 코딩된 앱의 보안 문제를 눈으로 확인하고, 평소 사용하는 AI 도구를 통해 직접 고칠 수 있게 돕는 **방어용 보안 점검 도구**입니다. OWASP ZAP, Burp Suite 같은 DAST(동적 애플리케이션 보안 테스트) 도구와 같은 범주이며, 차별점은 결과를 **보여주는 방식**과 **고치는 방식**에 있습니다.

> [!WARNING]
> 개발 초기 단계입니다. 현재는 네트워크를 쓰지 않는 정적 분석(Security Map)과 수정 프롬프트(Fix Prompt)만 동작하며, 동적 점검(Proof Replay)은 아직 구현되지 않았습니다.

## 만드는 이유

- AI가 만든 앱 상당수가 비밀값 노출, 권한 검사 누락 같은 **기본적인 문제**를 안고 배포됩니다.
- 정작 만든 사람은 자신의 앱을 보호할 줄 모르고, 코드를 직접 고치지도 않습니다. 항상 고치는 건 AI입니다.
- 그래서 경고 목록 대신 **시각화**, **재현 기록**, **AI에게 전달할 수정 프롬프트**를 만듭니다.

## 사용법

```bash
$ pnpm install && pnpm build
$ cargo run -p seethru-cli -- scan <프로젝트 경로>
```

결과 리포트는 `<프로젝트 경로>/.seethru/report.html`에 저장되며, 이 폴더는 자동으로 git에서 제외됩니다. 리포트는 외부 요청 없이 파일 하나로 열리고, 발견한 비밀 값은 모두 마스킹되어 원문이 남지 않습니다.

| 옵션                 | 설명                                                                              |
|----------------------|-----------------------------------------------------------------------------------|
| `--out FILE`         | HTML 리포트를 `FILE`에 저장합니다                                                 |
| `--json`             | HTML 대신 스캔 결과를 JSON으로 출력합니다                                         |
| `--lang ko`          | 요약과 리포트를 한국어로 보여 줍니다 (기본값 `en`)                                |
| `--no-config`        | 검사하는 프로젝트의 `seethru.toml`을 무시합니다 ([설정](#설정) 참고)              |
| `--build-output DIR` | `DIR`에 있는 Vite 또는 Next 빌드 결과물을 읽습니다. 프로젝트 안의 폴더여야 합니다 |
| `--sarif FILE`       | 다른 검사 도구가 SARIF 2.1.0으로 `FILE`에 쓴 결과를 함께 보여 줍니다. 최대 8개    |
| `--sarif-out FILE`   | seethru가 찾은 것을 SARIF 2.1.0으로 `FILE`에도 저장합니다                         |
| `--compile-commands FILE` | 프로젝트 안의 `compile_commands.json`을 읽어 어떤 C, C++ 파일이 빌드되는지 확인합니다 |


| 탐지 항목              | 설명                                                                            |
|--------------------|-------------------------------------------------------------------------------|
| Supabase RLS       | 마이그레이션 SQL에서 RLS가 꺼진 테이블, 조건 없이 모든 행을 연 정책                                    |
| Supabase 함수        | 누구나, 또는 로그인한 사용자가 `rpc()`로 부를 수 있는 `security definer` 함수 (RLS를 건너뜀)           |
| Supabase 뷰         | RLS를 건너뛰고 누구나, 또는 로그인한 사용자가 읽을 수 있는 뷰                                         |
| Supabase Storage   | 버킷의 모든 파일을 누구나, 또는 로그인한 모든 사용자에게 여는 Storage 정책                                |
| service_role 키 노출  | 브라우저 코드가 공개 환경변수로 service_role 키를 읽는 경우                                       |
| 확인 없는 service_role | 누가 부르는지 확인하지 않고 service_role 키를 쓰는 코드에 닿는 route, server action, Edge Function |
| 비밀 값 노출            | 코드, 빌드 결과물, 환경변수 파일에 들어 있는 API 키와 DB 접속 주소                                    |
| 펌웨어 설정           | ESP-IDF와 Zephyr 설정 파일에서 켜 둔 테스트용 설정, HTTP로 받는 업데이트, 건너뛰는 인증서 확인      |
| 열린 펌웨어 업데이트    | 누가 보내는지 확인하지 않고 펌웨어 업데이트를 쓰는 ESP-IDF 기기의 HTTP 경로                        |
| 스키마 없는 테이블         | 코드에서 쓰지만 저장소의 SQL 어디에도 만드는 구문이 없어 RLS를 확인할 수 없는 테이블                           |

## 설정

특정 경로를 검사에서 빼거나 의도한 탐지를 허용하려면, 검사할 프로젝트의 루트에 `seethru.toml`을 두세요. 이 파일은 없어도 됩니다.

```toml
exclude = ["legacy", "**/*.test.ts", "supabase/seed.sql"]

[[accept]]
rule = "supabase-policy-unrestricted"
path = "supabase/migrations/*_products.sql"
reason = "상품 목록은 일부러 공개함"

[[accept]]
id = "supabase-table-schema-missing:table:public.orders"
reason = "orders는 대시보드에서 만들었고 거기서 RLS를 켜 둠"
```

**`exclude`** 에 적은 파일과 폴더는 아예 읽지 않습니다.

- 패턴에는 `*`, `?`, `**`를 쓸 수 있습니다. `/`가 없는 패턴은 어느 깊이에 있든 이름이 맞으면 제외하므로, `legacy`는 모든 `legacy` 폴더를 뺍니다. `/`가 있는 패턴은 프로젝트 루트부터 맞추므로, 어느 깊이에서든 맞추려면 `**/`로 시작하세요.
- 패턴은 프로젝트 안을 가리켜야 합니다. `..`, `/`로 시작하는 경로, `\`는 쓸 수 없습니다.
- `.git`, `node_modules`, `.pnpm-store`, `.yarn`, `.seethru`는 항상 건너뛰므로 따로 적지 않아도 됩니다.
- 제외한 파일의 문제는 리포트에 나타나지 않습니다. 알고 있는 문제를 계속 보이게 두려면 `[[accept]]`를 쓰세요.

**`[[accept]]`** 는 조건에 맞는 탐지를 허용한 문제로 표시합니다. 항목마다 1~500자의 `reason`(사유)과 아래 키 중 하나 이상이 필요합니다. 키를 여러 개 적으면 모두 맞아야 합니다.

| 키     | 대상                                                                       |
|--------|----------------------------------------------------------------------------|
| `id`   | 문제 하나. 리포트의 Fix 패널과 `--json` 출력에 나오는 문제 ID로 지정합니다 |
| `rule` | 규칙 하나의 모든 탐지. 아래 표의 규칙 ID로 지정합니다                      |
| `path` | 패턴에 맞는 파일에서 보고된 탐지. 패턴은 `exclude`와 같은 방식으로 씁니다  |
| `engine` | 외부 검사 도구 하나의 결과. 리포트에 나오는 도구 이름으로 지정합니다 (예: `semgrep`) |
| `external-rule` | 외부 검사 도구의 규칙 하나의 결과. 리포트에 나오는 규칙 이름으로 지정합니다 |


| 규칙 ID                                  | 심각도    | 탐지 내용                                                                          |
|----------------------------------------|--------|--------------------------------------------------------------------------------|
| `supabase-rls-disabled`                | 치명적    | `public` 스키마의 테이블에 RLS가 꺼져 있음                                                  |
| `supabase-policy-unrestricted`         | 낮음~치명적 | 정책이 누구나, 또는 로그인한 모든 사용자에게 모든 행을 엶                                              |
| `supabase-function-bypasses-rls`       | 낮음~높음  | anon이나 로그인한 사용자가 `rpc()`로 부를 수 있는 `security definer` 함수가 RLS 없이 실행됨            |
| `supabase-view-bypasses-rls`           | 낮음~치명적 | `public` 스키마의 뷰가 RLS를 건너뛰고 anon이나 로그인한 사용자에게 읽힘                                |
| `supabase-storage-policy-unrestricted` | 낮음~치명적 | `storage.objects` 정책이 누구나, 또는 로그인한 모든 사용자에게 버킷의 모든 파일을 엶                       |
| `supabase-service-role-in-browser`     | 치명적    | 브라우저 코드가 공개 환경변수로 service_role 키를 읽음                                           |
| `supabase-service-role-unguarded`      | 중간~높음  | route, server action, Edge Function이 누가 부르는지 확인하지 않고 service_role 키를 쓰는 코드에 닿음 |
| `secret-in-browser-code`               | 치명적    | 브라우저로 전달되는 코드나 파일에 비밀 값이 있음                                                    |
| `secret-in-public-env-var`             | 치명적    | `VITE_` 같은 공개 접두사가 붙은 환경변수에 비밀 값이 있음                                           |
| `secret-in-source-code`                | 높음     | 서버 코드나 환경변수 파일처럼 브라우저로 가지 않는 파일에 비밀 값이 있음                                      |
| `supabase-table-schema-missing`        | 정보     | 코드에서 쓰는 테이블을 만드는 SQL이 저장소에 없음                                                  |
| `external`                             | 정보~높음  | 다른 검사 도구가 SARIF 파일로 알린 결과. seethru가 직접 확인한 것은 아님                              |
| `firmware-insecure-option-on`          | 중간~높음  | 테스트용으로만 쓰는 펌웨어 설정이 설정 파일에서 켜져 있음                                            |
| `firmware-ota-over-http`               | 높음     | 설정 파일이 펌웨어 업데이트를 암호화되지 않은 HTTP로 받을 수 있게 함                                    |
| `firmware-tls-verification-off`        | 높음     | 설정 파일이 기기가 서버 인증서 확인을 건너뛸 수 있게 함                                             |
| `firmware-ota-unguarded`               | 높음     | 기기의 HTTP 경로가 펌웨어 업데이트를 쓰는데 부른 쪽을 확인하는 코드를 찾지 못함                           |
| `secret-in-native-code`                | 높음     | C, C++ 코드나 펌웨어 설정 파일에 비밀 값이 있음                                               |

- 문제 ID는 규칙 ID 뒤에 그래프 노드를 붙인 형태입니다. 예를 들어 `supabase-rls-disabled:table:public.orders`입니다.
- 비밀 값 탐지의 문제 ID는 파일, 비밀 값 종류, 그 파일에서 같은 종류 중 몇 번째인지로 이루어집니다. 예를 들어 `secret-in-source-code:secret:src/pay.ts:stripeSecretKey:1`입니다. 파일의 다른 코드가 바뀌어도 ID는 그대로입니다.
- 허용한 문제는 리포트와 CLI 요약에서 사유와 함께 따로 보여 줍니다. 전체 개수에는 들어가지 않고 그래프 색에도 반영되지 않습니다.
- `seethru.toml`을 쓸 수 없으면 무시하지 않고, 문제가 있는 줄을 알려 주며 검사를 멈춥니다. 모르는 키, 빠진 사유, 없는 규칙 ID, 잘못된 패턴이 여기에 해당합니다. 파일은 64KB 이하의 일반 파일이어야 하고, `exclude` 패턴은 256개, `[[accept]]` 항목은 1,000개까지 쓸 수 있습니다.
- `--no-config`를 붙이면 이 파일을 무시합니다. 다른 사람이 만든 프로젝트를 검토할 때 그 프로젝트의 설정이 문제를 숨기지 못하도록 이 옵션을 쓰세요.

## 진입점

seethru는 진입점마다 실행되는 코드를 따라가서, 그 코드가 service_role 키를 쓰기 전에 부른 사람을 확인하는지 봅니다.

- 진입점은 Next route handler(`app/**/route.ts`, `pages/api/**`), `"use server"` 파일이 내보낸 함수, Supabase Edge Function입니다.
- 사용자가 없을 때 `return`, `throw`, `redirect()`로 일찍 멈추면 확인으로 인정합니다. 처리 함수 안에 있어도 되고, 처리 함수가 먼저 부르는 보조 함수 안에 있어도 됩니다.
- 알아보는 확인은 `supabase.auth.getUser()`, `getClaims()`, `getSession()`(서버에서는 약한 확인), next-auth `getServerSession()`, Clerk `auth()`, `currentUser()`, `auth.protect()`, Stripe 웹훅 서명, Firebase `verifyIdToken()`, jose나 jsonwebtoken의 JWT 확인, 요청 값과 비밀 환경변수 비교입니다.
- 사용자를 확인하는 middleware, 모르는 인증 라이브러리, 읽을 수 없는 확인 뒤의 401 응답처럼 판단할 수 없으면 추측하지 않고 그 진입점은 알리지 않습니다.
- 다른 함수에 인자로 넘긴 Supabase 클라이언트는 아직 따라가지 않습니다.

## 빌드 결과물

seethru는 빌드를 직접 실행하지 않습니다. 프로젝트를 먼저 빌드한 뒤 결과물 폴더를 넘겨 주세요.

```bash
$ seethru scan . --build-output dist
$ seethru scan . --build-output .next
```

- 폴더는 검사하는 프로젝트 안에 있어야 하고 심볼릭 링크이면 안 됩니다. `exclude` 패턴에 맞아도 이 폴더는 읽습니다.
- **Vite**: `vite.config`에서 `build.manifest`와 `build.sourcemap`을 켜면 번들에 들어간 모든 파일을 볼 수 있습니다. 모든 청크에 소스맵이 있으면 번들에 들어가지 않은 파일은 더 이상 브라우저 코드로 취급하지 않습니다.
- **Next**: `.next`를 읽습니다. `"use client"` 파일은 빌드 매니페스트로 확인합니다. 브라우저에 닿는 모든 파일을 확인하려면 `next.config`에서 `productionBrowserSourceMaps: true`를 설정하세요. 빌드 매니페스트에 있는 라우트는 소스에서 처리 함수를 찾지 못해도 진입점으로 나타납니다.
- 빌드 결과물로 확인한 파일의 탐지에는 "추정" 표시가 붙지 않습니다. 번들에서 찾은 비밀 값은 소스맵을 따라 원래 소스 줄을 가리킵니다.
- 소스 파일 중 하나라도 빌드 결과물보다 2초를 넘게 새로우면 빌드 결과물을 쓰지 않고, 리포트의 "확인하지 못한 것"에 그 사실을 적습니다. 다시 빌드한 뒤 실행하세요.
- 옵션이 없어도 `.next/server`와 `.next/standalone`은 서버 코드, `.next/static`은 브라우저 코드, `.next/cache`는 빌드 캐시로 취급합니다.

## C, C++와 펌웨어

seethru는 C, C++ 소스와 펌웨어 설정 파일을 빌드하지 않고 읽습니다. 이 부분은 새로 생겼고, 일부러 범위를 좁게 잡았습니다.

- 펌웨어 프로젝트는 `sdkconfig` 파일(ESP-IDF), `prj.conf`(Zephyr), `platformio.ini`, `.ino` 스케치로 알아봅니다.
- 읽는 설정 파일은 `sdkconfig`, `sdkconfig.defaults`와 그 변형, `prj.conf`, `prj_*.conf`입니다. 켜져 있다고 적힌 설정만 알립니다. 파일에 없는 설정은 아무것도 말해 주지 않으므로 "secure boot가 꺼져 있다"고 알리지 않습니다. CI용 파일과 `test`, `tests`, `examples` 폴더 아래의 파일은 건너뜁니다.
- 진입점은 ESP-IDF HTTP 서버의 경로 중 `.uri`와 `.handler`를 적은 `httpd_uri_t` 값입니다. 처리 함수에서 함수 이름으로 호출을 따라가서 `esp_ota_write`나 `esp_https_ota`에 닿고, 그 사이에 부른 쪽을 확인하는 것처럼 보이는 함수가 없으면 그 경로를 알립니다.
- 부른 쪽을 확인하는 것처럼 보이면 알리지 않습니다. `auth`, `password`, `token`, `session`, `verify` 같은 단어가 들어간 호출이나 문자열, 그런 일을 하는 래퍼로 바꿔 끼운 처리 함수, 찾을 수 없는 처리 함수가 여기에 해당합니다.
- 매크로, 함수 포인터, C++ 오버로드, 생성된 코드는 따라가지 않습니다. 메모리 안전 버그는 찾지 않습니다. 그런 문제는 다른 검사 도구로 찾고 결과를 `--sarif`로 넘겨 주세요.
- C, C++ 파일과 펌웨어 설정 파일에서 찾은 비밀 값은 규칙 `secret-in-native-code`로 알립니다. 개인 키는 본문이 있을 때만 알리므로, 키 머리글 이름만 다루는 파서 코드는 알리지 않습니다.
- `--compile-commands`는 `compile_commands.json`을 데이터로만 읽습니다. 그 안의 명령은 실행하지 않습니다. 빌드 목록에 없는 소스 파일의 탐지는 "확인 필요"로 표시합니다.
- `CMakeLists.txt`, `platformio.ini`, `sdkconfig` 파일 옆의 루트 `build`, `out` 폴더는 읽지 않고, `.pio`, `managed_components`, `CMakeFiles` 폴더는 항상 건너뜁니다.

## 다른 검사 도구의 결과

seethru는 다른 검사 도구가 찾은 것을 자기 탐지 옆에 함께 보여 줄 수 있습니다. 검사 도구는 직접 실행하고, 결과를 SARIF 2.1.0으로 저장한 뒤 그 파일을 넘겨 주세요.

```bash
$ seethru scan . --sarif semgrep.sarif --sarif clang.sarif
$ seethru scan . --sarif-out seethru.sarif
```

- seethru는 검사 도구를 실행하지 않습니다. 넘겨 준 파일만 읽고, 프로젝트 안에서 SARIF 파일을 스스로 찾지 않습니다.
- 결과 하나하나는 규칙 `external`의 탐지가 되고 "확인 필요"로 표시됩니다. seethru가 직접 확인한 것이 아니라서 심각도는 높음까지만 올라갑니다.
- 검사 도구가 쓴 문장은 옮기지 않습니다. 메시지, 코드 조각, 도움말에는 비밀 값이나 AI 도구를 노린 지시가 들어 있을 수 있어서, 리포트에는 도구 이름, 규칙 이름, CWE 번호, 파일과 줄만 남깁니다. 제목, 설명, 수정 프롬프트는 seethru가 씁니다.
- 파일이 검사하는 프로젝트 안에 실제로 있는 결과만 남깁니다. 다른 경로, 제외한 파일, 원격 주소를 가리키거나 위치를 알 수 없는 결과는 빼고, 몇 개를 뺐는지 리포트에 적습니다.
- 결과를 허용하려면 `[[accept]]`에 `engine`, `external-rule`, `path`를 쓰세요. `rule = "external"`만 적으면 모든 검사 도구의 결과를 한꺼번에 숨기게 되므로 받지 않습니다.
- `--sarif-out`은 seethru의 탐지를 SARIF로 저장합니다. GitHub code scanning에 올릴 때 쓸 수 있습니다. 허용한 탐지는 숨김으로 표시됩니다. 다른 검사 도구에서 온 결과는 다시 쓰지 않습니다.
- Joern의 `joern-scan`은 텍스트만 출력하고 SARIF 옵션이 없습니다. Joern은 `cpg.finding.toSarifJson()`을 부르는 스크립트로 SARIF를 내보냅니다. 방법은 Joern 저장소의 `tests/test-sarif.sc`에 있습니다.

## 에이전트 스킬

이 저장소는 Claude Code 플러그인 마켓플레이스이기도 합니다. `seethru` 플러그인은 코딩 에이전트가 검사를 실행하고, 리포트를 읽고, 탐지를 순서대로 고친 뒤 다시 검사해 확인하게 하는 스킬을 더합니다.

Claude Code 안에서 설치합니다.

```
/plugin install seethru --marketplace Quant-TheodoreFelix/seethru
```

이전 버전에서는 마켓플레이스를 먼저 추가합니다.

```
/plugin marketplace add Quant-TheodoreFelix/seethru
/plugin install seethru@seethru
```

업데이트합니다.

```
/plugin marketplace update seethru
/plugin update seethru@seethru
```

터미널에서는 같은 명령을 `claude plugin marketplace add`, `claude plugin install`, `claude plugin marketplace update`, `claude plugin update`로 실행합니다. 업데이트한 뒤에는 Claude Code를 다시 시작하세요. 지우려면 `/plugin uninstall seethru@seethru`를 실행합니다.

- 에이전트에게 seethru로 프로젝트를 검사해 달라고 하거나 `/seethru:seethru`로 부릅니다.
- 스킬에는 검사기가 들어 있지 않습니다. [사용법](#사용법)대로 seethru를 빌드한 뒤 `SEETHRU_BIN`을 `target/release/seethru`로 지정하거나, 그 파일을 `PATH`에 두세요.
- 플러그인 없이 쓰려면 `plugins/seethru/skills/seethru` 폴더를 `~/.claude/skills/`에 복사하세요.

## 안전 설계

**seethru는 공격 도구가 아닙니다.** 아래 원칙은 선택 사항이 아니라 *모든 기능*에 적용되는 필수 요구사항입니다.

1. **소유권 인증 없이는 동적 점검 불가**: DNS TXT 레코드나 `/.well-known/` 와 같은 파일로 소유를 확인한 도메인만 점검하고, 인증은 주기적으로 다시 확인합니다.
2. **범위 고정(scope lock)**: 인증된 도메인 밖으로 요청을 보내지 않습니다. 리다이렉트(redirect)로 외부 도메인에 닿으면 바로 중단합니다.
3. **비파괴적 점검만**: 데이터 삭제·수정, 서비스 거부 유발, 대량 요청을 하지 않습니다. 사용자가 만든 테스트 계정만 사용합니다.
4. **레이트 리밋**: 타겟 서버에 부담을 주지 않도록 요청 속도를 제한합니다.
5. **실제 사용자 데이터 비수집**: 재현 중 노출된 실제 데이터는 마스킹(masking)하고 저장하지 않습니다.
6. **감사 로그**: 모든 점검 요청을 기록하고 사용자가 열람할 수 있게 합니다.
7. **스테이징 우선**: 프로덕션을 점검할 때는 명시적인 확인을 받습니다.

## 기술 스택

제로 트러스트(Zero-Trust)와 폐쇄 친화적(Air-Gapped) 환경을 전제로 단일 바이너리와 작은 의존성 트리를 우선합니다.

| 영역             | 선택                                                |
|------------------|-----------------------------------------------------|
| 엔진             | Rust 단일 바이너리, oxc (JS/TS 파서)                |
| 웹 UI            | React, React Flow, ELK.js, Motion, Vite, TypeScript |

## 저장소 구조

| 경로                      | 역할                                                   |
|---------------------------|--------------------------------------------------------|
| `crates/seethru-core`     | 공통 타입과 그래프 모델                                |
| `crates/seethru-analyzer` | 정적 분석 (Security Map)                               |
| `crates/seethru-guard`    | 소유권 인증, 범위 고정, 레이트 리밋, 감사 로그, 마스킹 |
| `crates/seethru-probe`    | 동적 점검 (Proof Replay)                               |
| `crates/seethru-fix`      | 수정 프롬프트 생성 (Fix Prompt)                        |
| `crates/seethru-report`   | 로컬 HTML 리포트                                       |
| `crates/seethru-mcp`      | MCP 서버                                               |
| `crates/seethru-cli`      | `seethru` 실행 파일                                    |
| `web`                     | Security Map, Proof Replay 웹 UI                       |
| `schema`                  | 스캔 리포트 JSON Schema                                |
| `fixtures`                | 테스트용 취약 예제 프로젝트 (실제 키 없음)             |
| `plugins`                 | 에이전트 스킬. `.claude-plugin/marketplace.json`으로 배포 |

## 기여하기

개발 환경, 검사 방법, 새 규칙을 추가하는 방법은 [CONTRIBUTING_KR.md](CONTRIBUTING_KR.md)를 참고하세요.

## 책임 있는 사용

본인이 소유했거나 점검 권한을 받은 앱에만 사용하세요. seethru는 소유권 인증을 통과하지 않은 타겟에는 동적 점검을 하지 않습니다.

## 라이선스

[Apache License 2.0](LICENSE)을 따릅니다.
