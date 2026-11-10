# seethru

<div align="center">

**"_See through_ your app before attackers do."  
당신의 앱을 공격자보다 먼저 꿰뚫어 보세요.**

[English](README.md) | 한국어

</div>

seethru는 바이브 코딩된 앱의 보안 문제를 눈으로 확인하고, 평소 사용하는 AI 도구를 통해 직접 고칠 수 있게 돕는 **방어용 보안 점검 도구**입니다. OWASP ZAP, Burp Suite 같은 DAST(동적 애플리케이션 보안 테스트) 도구와 같은 범주이며, 차별점은 결과를 **보여주는 방식**과 **고치는 방식**에 있습니다.

> [!WARNING]
> 개발 초기 단계입니다. 네트워크를 쓰지 않는 정적 분석(Security Map)과 수정 프롬프트(Fix Prompt)가 동작합니다. 동적 점검(Proof Replay)은 첫 단계만 있습니다. 소유를 확인한 실행 중인 앱의 첫 페이지에서 보안 헤더와 CORS를 확인합니다. 테스트 계정 사이의 접근 문제를 재현하는 기능은 아직 구현되지 않았습니다.

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

seethru는 기본으로 파일만 읽습니다. 무언가를 실행하거나 보내는 것은 옵션으로 지정했을 때뿐이고, 실행하기 전에 무엇을 실행하는지 먼저 출력합니다.

모든 옵션, `seethru.toml`, 문제 ID, 종료 코드, 프로젝트 종류별 안내(Next와 Vite, Supabase, C, C++와 펌웨어, Rust, SARIF 결과)는 [USAGE_KR.md](USAGE_KR.md)에 있습니다.

## 탐지 항목

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
| 비밀 값 나눗셈        | 컴파일된 Rust 코드에서, 쓰고 나서 지우는 값으로 하는 나눗셈 (걸리는 시간으로 값이 새어 나감)      |
| 프로그램을 멈추는 검사 | 커널, 펌웨어, FFI 라이브러리의 컴파일된 Rust 코드에서, 외부 진입점으로 들어온 값에 panic하는 검사 |
| Cargo 의존성         | `Cargo.lock`이 없는 프로젝트에서 한 버전으로 고정되지 않은 git 의존성과 `*` 버전                   |
| 사라진 메모리 소거    | 빌드된 Rust 프로그램에서, 소스에는 메모리를 지우는 줄이 있는데 프로그램에는 그 코드가 없는 경우. `--tool` 필요 |
| 보안 헤더            | 소유한 실행 중인 앱의 첫 페이지에 콘텐츠 보안 정책, `nosniff`, 프레임 보호, HSTS가 없는 경우. `--probe` 필요 |
| 열린 CORS            | 소유한 실행 중인 앱이 아무 사이트나 방문자의 쿠키와 함께 응답을 읽게 하는 경우. `--probe` 필요   |
| 스키마 없는 테이블         | 코드에서 쓰지만 저장소의 SQL 어디에도 만드는 구문이 없어 RLS를 확인할 수 없는 테이블                           |

## 파일 읽기 밖의 기능

아래 기능은 모두 옵션으로 켜기 전에는 꺼져 있습니다.

- **빌드된 프로그램.** `seethru scan . --build --tool objdump --tool dwarfdump`는 Rust 소스에 적은 메모리 소거가 컴파일러가 만든 프로그램에 남아 있는지 확인합니다. `--tool`은 seethru가 실행해도 되는 외부 도구를 지정합니다. [USAGE_KR.md](USAGE_KR.md#메모리-소거가-빌드된-프로그램에-남아-있는지-확인하기)를 참고하세요.
- **실행 중인 앱.** `seethru own URL`이 앱에 올려 둘 한 줄을 알려 줍니다. 그 뒤 `seethru scan . --probe URL --staging --tool curl`이 읽기만 하는 요청 몇 개를 천천히 보내 첫 페이지의 보안 헤더와 CORS를 확인합니다. 요청은 보내기 전에 모두 감사 로그에 기록합니다. [USAGE_KR.md](USAGE_KR.md#실행-중인-앱-점검하기)를 참고하세요.
- **코딩 에이전트 (MCP).** `seethru mcp --root DIR`을 쓰면 Claude Code나 Cursor 같은 에이전트가 폴더를 검사하고 탐지를 읽을 수 있습니다. 무엇을 실행해도 되는지는 서버를 띄울 때 준 플래그로만 정해지고, 에이전트가 바꿀 수 없습니다. [USAGE_KR.md](USAGE_KR.md#코딩-에이전트에서-seethru-쓰기-mcp)를 참고하세요.

## 에이전트 스킬

이 저장소는 Claude Code 플러그인 마켓플레이스이기도 합니다. `seethru` 플러그인은 코딩 에이전트가 검사를 실행하고, 리포트를 읽고, 탐지를 순서대로 고친 뒤 다시 검사해 확인하게 하는 스킬을 더합니다. 스킬은 에이전트가 빌드하거나, 외부 도구를 실행하거나, 실행 중인 앱을 점검하는 단계마다 먼저 사용자에게 묻게 합니다. Claude Code 안에서 `/plugin install seethru --marketplace Quant-TheodoreFelix/seethru`로 설치합니다. 그 밖의 설치, 업데이트, 삭제 명령은 [USAGE_KR.md](USAGE_KR.md#에이전트-스킬)에 있습니다.

## 안전 설계

**seethru는 공격 도구가 아닙니다.** 아래 원칙은 선택 사항이 아니라 *모든 기능*에 적용되는 필수 요구사항입니다.

1. **소유권 인증 없이는 동적 점검 불가**: DNS TXT 레코드나 `/.well-known/` 와 같은 파일로 소유를 확인한 도메인만 점검하고, 인증은 주기적으로 다시 확인합니다.
2. **범위 고정(scope lock)**: 인증된 도메인 밖으로 요청을 보내지 않습니다. 리다이렉트(redirect)로 외부 도메인에 닿으면 바로 중단합니다.
3. **비파괴적 점검만**: 데이터 삭제·수정, 서비스 거부 유발, 대량 요청을 하지 않습니다. 사용자가 만든 테스트 계정만 사용합니다.
4. **레이트 리밋**: 타겟 서버에 부담을 주지 않도록 요청 속도를 제한합니다.
5. **실제 사용자 데이터 비수집**: 재현 중 노출된 실제 데이터는 마스킹(masking)하고 저장하지 않습니다.
6. **감사 로그**: 모든 점검 요청을 기록하고 사용자가 열람할 수 있게 합니다.
7. **스테이징 우선**: 프로덕션을 점검할 때는 명시적인 확인을 받습니다.

지금의 실행 중인 앱 점검은 이 일곱 가지를 모두 따릅니다. 소유는 `/.well-known/` 아래의 파일로 확인하고(DNS TXT 방식은 아직 없습니다), `GET` 요청만 보내며, 테스트 계정은 아직 쓰지 않습니다. 자세한 내용은 [USAGE_KR.md](USAGE_KR.md#실행-중인-앱-점검하기)에 있습니다.

## 기술 스택

제로 트러스트(Zero-Trust)와 폐쇄 친화적(Air-Gapped) 환경을 전제로 단일 바이너리와 작은 의존성 트리를 우선합니다. 의존성은 정확한 버전으로 고정하고 `unsafe` 코드는 금지합니다.

| 영역   | 선택                                                                       |
|--------|----------------------------------------------------------------------------|
| 엔진   | Rust 1.99.1 (2024 에디션), 단일 바이너리, oxc (JS/TS 파서)                 |
| 데이터 | serde, serde_json, schemars (JSON Schema), toml, lexopt (CLI 인자)         |
| 웹 UI  | React 19, React Flow, ELK.js, Motion, Vite 8, TypeScript 7, pnpm으로 빌드  |

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
