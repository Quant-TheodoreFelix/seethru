# seethru 사용법

[English](USAGE.md) | 한국어

이 문서는 seethru를 실행하는 방법, 모든 옵션, 설정 방법, 그리고 seethru가 읽는 프로젝트 종류별로 알아 둘 점을 설명합니다. seethru가 무엇이고 왜 만드는지는 [README](README_KR.md)를 참고하세요.

- [빌드와 실행](#빌드와-실행)
- [명령](#명령)
- [옵션](#옵션)
- [종료 코드](#종료-코드)
- [설정](#설정)
- [진입점](#진입점)
- [빌드 결과물](#빌드-결과물)
- [C, C++와 펌웨어](#c-c와-펌웨어)
- [Rust](#rust)
- [다른 검사 도구의 결과](#다른-검사-도구의-결과)
- [에이전트 스킬](#에이전트-스킬)

## 빌드와 실행

```bash
$ pnpm install && pnpm build
$ cargo run -p seethru-cli -- scan <프로젝트 경로>
```

결과 리포트는 `<프로젝트 경로>/.seethru/report.html`에 저장되며, 이 폴더는 자동으로 git에서 제외됩니다. 리포트는 외부 요청 없이 파일 하나로 열리고, 발견한 비밀 값은 모두 마스킹되어 원문이 남지 않습니다.

`pnpm build`는 HTML 리포트 안에 넣는 웹 UI를 만듭니다. 이 단계를 건너뛰면 HTML 리포트를 쓸 수 없습니다.

`target/release/seethru`에 릴리스 바이너리가 필요하면 `pnpm build` 다음에 `cargo build --release -p seethru-cli`를 실행하세요.

## 명령

| 명령                     | 설명                                                                  |
|--------------------------|-----------------------------------------------------------------------|
| `seethru scan [PATH]`    | 프로젝트 폴더를 분석합니다 (기본값은 현재 폴더)                       |
| `seethru schema`         | 스캔 리포트의 JSON Schema를 출력합니다                                |
| `seethru --version`      | 버전을 출력합니다                                                     |
| `seethru --help`         | 사용법 문구를 출력합니다. 인자 없이 `seethru`만 실행해도 같습니다     |

scan 명령의 전체 형태는 다음과 같습니다.

```bash
seethru scan [PATH] [--out FILE] [--json] [--lang LANG] [--no-config]
             [--build-output DIR] [--sarif FILE]... [--sarif-out FILE]
             [--compile-commands FILE] [--llvm-ir PATH]... [--build]
```

## 옵션

| 옵션                 | 설명                                                                              |
|----------------------|-----------------------------------------------------------------------------------|
| `--out FILE`         | HTML 리포트를 `FILE`에 저장합니다 (기본값은 `PATH/.seethru/report.html`)          |
| `--json`             | HTML 대신 스캔 결과를 JSON으로 출력합니다                                         |
| `--lang ko`          | 요약과 리포트를 한국어로 보여 줍니다 (기본값 `en`)                                |
| `--no-config`        | 검사하는 프로젝트의 `seethru.toml`을 무시합니다 ([설정](#설정) 참고)              |
| `--build-output DIR` | `DIR`에 있는 Vite 또는 Next 빌드 결과물을 읽습니다. 프로젝트 안의 폴더여야 합니다 ([빌드 결과물](#빌드-결과물) 참고) |
| `--sarif FILE`       | 다른 검사 도구가 SARIF 2.1.0으로 `FILE`에 쓴 결과를 함께 보여 줍니다. 최대 8개 ([다른 검사 도구의 결과](#다른-검사-도구의-결과) 참고) |
| `--sarif-out FILE`   | seethru가 찾은 것을 SARIF 2.1.0으로 `FILE`에도 저장합니다                         |
| `--compile-commands FILE` | 프로젝트 안의 `compile_commands.json`을 읽어 어떤 C, C++ 파일이 빌드되는지 확인합니다 ([C, C++와 펌웨어](#c-c와-펌웨어) 참고) |
| `--llvm-ir PATH`     | Rust 프로젝트의 컴파일 결과를 읽습니다. `.ll` 파일이나 그런 파일이 든 폴더이고 여러 번 줄 수 있습니다 ([Rust](#rust) 참고) |
| `--build`            | Rust 프로젝트를 cargo로 빌드하고 그 결과를 읽습니다. 프로젝트의 빌드 스크립트와 매크로가 실행되므로 믿을 수 있는 코드에만 쓰세요 ([Rust](#rust) 참고) |

- `--lang`에는 `en`이나 `ko`를 줍니다. 다른 값은 오류입니다.
- `--json`과 `--out`은 함께 쓸 수 없습니다.
- `--sarif-out`은 모든 `--sarif` 파일, 그리고 `--out`과 다른 파일이어야 합니다.
- `--json`은 리포트를 터미널에 출력합니다. 쓰지 않으면 seethru가 짧은 요약을 출력하고, 이어서 저장한 리포트의 경로를 알려 줍니다.

## 종료 코드

| 코드 | 의미                                                                                  |
|------|---------------------------------------------------------------------------------------|
| `0`  | 검사가 끝났습니다. 탐지가 있어도 종료 코드는 바뀌지 않습니다                          |
| `1`  | 검사를 실행하지 못했습니다. stderr의 한 줄짜리 `error:`가 고칠 입력을 알려 줍니다     |
| `2`  | 인자가 잘못됐습니다. seethru가 오류와 사용법 문구를 출력합니다                        |

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
| `secret-dependent-division`            | 중간     | 컴파일된 코드가 프로그램이 쓰고 나서 지우는 메모리에서 나온 값으로 나눗셈을 함                         |
| `cargo-dependency-not-pinned`          | 낮음     | git에서 받는 Cargo 의존성에 `rev`가 없거나 버전이 `*`이고, 프로젝트에 `Cargo.lock`이 없음          |

### 문제 ID

- 문제 ID는 규칙 ID 뒤에 그래프 노드를 붙인 형태입니다. 예를 들어 `supabase-rls-disabled:table:public.orders`입니다.
- `secret-dependent-division` 문제의 ID는 파일과 그 파일 안에서의 순서로 이루어집니다. 예를 들어 `secret-dependent-division:file:mldsa/src/sign.rs:2`입니다. 줄 번호는 들어가지 않습니다.
- 비밀 값 탐지의 문제 ID는 파일, 비밀 값 종류, 그 파일에서 같은 종류 중 몇 번째인지로 이루어집니다. 예를 들어 `secret-in-source-code:secret:src/pay.ts:stripeSecretKey:1`입니다. 파일의 다른 코드가 바뀌어도 ID는 그대로입니다.

### 허용한 문제와 오류

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

## Rust

seethru는 루트 `Cargo.toml`에서 Cargo 프로젝트를 읽고, 크레이트와 그 사이의 의존 관계를 그립니다. Rust에서 중요한 검사는 컴파일 결과에서 합니다. 컴파일러가 작성한 코드를 다시 바꾸기 때문입니다.

- 크레이트는 루트 매니페스트에서 찾습니다. 루트 패키지, `[workspace] members`(`exclude` 반영), 그리고 거기서 `path` 의존성으로 닿는 크레이트입니다. `Cargo.toml` 옆의 `target` 폴더는 소스로 읽지 않습니다.
- `rev`가 없는 git 의존성과 `*` 버전은 프로젝트에 `Cargo.lock`이 없을 때만 알립니다.
- seethru는 요청하지 않으면 `cargo`를 실행하지 않습니다. 컴파일된 코드를 검사하려면 `--build`로 seethru가 빌드하게 하거나(아래), 직접 빌드한 뒤 결과를 넘겨 주세요.

```bash
RUSTFLAGS="--emit=llvm-ir,asm -C debuginfo=line-tables-only" cargo build --release
seethru scan . --llvm-ir target/release/deps
```

- `--target`이나 `build.target` 설정을 쓰면 파일은 `target/<triple>/release/deps`에 있습니다.
- 컴파일 결과가 소스보다 오래됐는지는 seethru가 알 수 없습니다. 코드를 바꿀 때마다 다시 빌드한 뒤 검사하세요.

- `--llvm-ir`에는 `.ll` 파일이나 폴더를 줍니다. 프로젝트 밖에 있어도 됩니다. `.ll` 파일 옆에 이름이 같은 `.s` 파일이 있으면 그 기계어로 읽습니다. 파일은 1,024개, 하나에 1GB, 합계 2GB까지입니다. 이만큼 읽으면 메모리를 몇 GB 쓸 수 있습니다.
- **비밀로 보는 것.** 코드가 일부러 volatile 쓰기로 지우는 메모리입니다. `zeroize()` 호출이 여기에 해당합니다. 그 메모리에서 읽은 값을 함수 호출, 복사, 돌려받은 포인터를 따라 추적합니다. 타입이 drop될 때 알아서 지우는 메모리는 비밀로 보지 않습니다. 해시 상태는 공개 값만 담았을 때도 스스로 지우기 때문입니다.
- **알리는 것.** 그런 값으로 하는 나눗셈과 나머지 연산입니다(`secret-dependent-division`). 대부분의 프로세서에서 나눗셈에 걸리는 시간은 숫자에 따라 달라집니다. `.s` 파일이 있으면, 그 소스 줄에 나눗셈 명령이 있을 때 `추정`으로 알리고, 컴파일러가 상수 나눗셈을 곱셈으로 바꾼 경우는 알리지 않습니다. `.s` 파일이 없으면 `확인 필요`입니다.
- **아직 확인하지 않는 것.** 비밀에 따라 갈리는 분기와 표 조회, 그리고 소거가 컴파일 뒤에도 남는지입니다. 둘 다 시험해 봤지만 틀린 결과가 너무 많아 넣지 않았습니다. 리포트는 매번 이 사실을 알립니다.
- 컴파일된 파일 밖의 호출자만 지우는 비밀, 메모리에 저장된 포인터 뒤의 비밀은 따라가지 못합니다. 라이브러리의 결과는 최종 링크 전 단계입니다. 탐지가 없다고 상수 시간이라는 뜻은 아닙니다.
- 컴파일 결과 안의 경로가 검사하는 프로젝트를 가리켜야 합니다. 같은 체크아웃에서 빌드하거나 `--remap-path-prefix`로 상대 경로로 만드세요.

### seethru가 빌드하게 하기

```bash
seethru scan . --build
```

seethru가 프로젝트의 무언가를 실행하는 경우는 `--build` 하나뿐입니다. 옵션을 주지 않으면 꺼져 있습니다.

- **믿을 수 있는 코드에만 쓰세요.** cargo 빌드는 프로젝트와 그 의존성의 `build.rs` 스크립트와 매크로를 이 컴퓨터에서 실행합니다. seethru는 이것을 막거나 격리하지 못합니다. 믿지 못하는 저장소는 `--build` 없이 검사하세요.
- `Cargo.toml`이 있는 폴더에서 `cargo build --release --locked --offline --target-dir PATH/.seethru/build/<project>`를 실행하고, 실행 전에 그 명령을 보여 줍니다. 타겟이나 컴파일러 플래그 같은 프로젝트의 `.cargo/config.toml` 설정은 평소처럼 적용됩니다.
- 아무것도 내려받지 않습니다. 프로젝트에 `Cargo.lock`이 있어야 하고, 의존성과 툴체인이 이미 컴퓨터에 있어야 합니다. 없으면 가져오지 않고 빌드가 실패하며, 직접 실행할 명령을 알려 줍니다. lock 파일이 없으면 `cargo generate-lockfile`, 의존성이 없으면 `cargo fetch`, 툴체인이 없으면 `rustup toolchain install`입니다.
- 결과는 `PATH/.seethru/build` 아래에 프로젝트마다 폴더를 만들어 씁니다. `target` 폴더는 건드리지 않습니다. 이 폴더는 커질 수 있고, 언제든 지워도 됩니다.
- seethru는 이 빌드에서만 컴파일러 앞에 자신을 끼워(`RUSTC_WRAPPER`) 필요한 출력을 더합니다. 프로젝트의 컴파일러 플래그는 그대로 유지됩니다. 프로젝트가 sccache 같은 자체 래퍼를 쓰고 있어도 이 빌드에서는 쓰이지 않습니다.
- 실행할 때마다 다시 빌드하므로 결과가 항상 소스와 맞습니다. 빌드 설정, 의존성, 툴체인이 바뀌면 폴더를 지우고 처음부터 한 번 다시 빌드합니다.
- 빌드가 실패하면 오류로 끝내고 리포트를 만들지 않습니다.
- 컴파일은 됐지만 링크가 안 되는 프로그램도 검사합니다. 검사는 컴파일된 코드를 읽을 뿐 링크된 파일이 필요하지 않기 때문입니다. 커널, 펌웨어, `main`이 없는 시험용 프로그램에서 흔합니다. 이런 경우 seethru가 그 사실을 알려 줍니다.
- `PATH` 안에서 찾은 Cargo 프로젝트 중 다른 프로젝트에 속하지 않은 것을 모두 빌드합니다. 그래서 `core/`나 `apps/desktop/src-tauri/` 같은 하위 폴더의 프로젝트도 됩니다. 프로젝트마다 `Cargo.lock`이 있어야 합니다. 하나라도 실패하면 검사를 멈춥니다. 이런 프로젝트가 8개를 넘으면 폴더를 하나씩 검사하세요.
- 워크스페이스라면 멤버 폴더가 아니라 워크스페이스 루트를 주세요.
- 컴파일 결과는 소스가 `PATH` 안에 있는 크레이트 것만 남깁니다. 레지스트리나 git에서 온 의존성은 평소처럼 빌드하지만 읽지 않으므로, 비밀 값이 그 안으로 들어간 뒤는 따라가지 못합니다.
- 시간 제한은 없습니다. 빌드가 멈추면 Ctrl-C로 중단하세요.
- `--build`와 `--llvm-ir`는 함께 쓸 수 있습니다.

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
- 스킬에는 검사기가 들어 있지 않습니다. [빌드와 실행](#빌드와-실행)대로 seethru를 빌드한 뒤 `SEETHRU_BIN`을 `target/release/seethru`로 지정하거나, 그 파일을 `PATH`에 두세요.
- 플러그인 없이 쓰려면 `plugins/seethru/skills/seethru` 폴더를 `~/.claude/skills/`에 복사하세요.
