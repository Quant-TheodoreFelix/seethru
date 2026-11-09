# seethru에 기여하기

<div align="center">

[English](CONTRIBUTING.md) | 한국어

</div>

가장 먼저 도와주셔서 고맙습니다. seethru는 앱의 보안 문제를 점검하는 도구라서, 변경 사항은 잘 동작하는 것과 함께 사용자와 사용자의 데이터를 안전하게 지켜야 합니다. Pull Request를 열기 전에 이 문서를 읽어 주세요.

## 기본 원칙

- 모든 기능은 [안전 설계](README_KR.md#안전-설계)를 따릅니다. 소유권 인증 없이 타겟을 점검하거나, 인증된 범위를 벗어나거나, 데이터를 바꾸거나, 대량 요청을 보내게 만드는 변경은 병합하지 않습니다.
- 정적 분석은 네트워크를 사용하지 않습니다. 분석기, 수정 프롬프트, HTML 리포트는 네트워크에 접속하지 않습니다. HTTP 클라이언트에 의존할 수 있는 크레이트는 `seethru-guard`뿐이며, `deny.toml`이 이를 강제합니다.
- 실제 비밀 값은 물론, 비밀 값처럼 보이는 문자열도 커밋하지 않습니다. Stripe 키, AWS 액세스 키, JWT처럼 생긴 문자열은 비밀 값 스캐너도 사람도 진짜와 구별하지 못합니다. 테스트에 쓰는 가짜 값은 `crates/seethru-analyzer/tests/secrets.rs`처럼 실행할 때 조각을 이어 붙여 만듭니다.
- 픽스처는 직접 만듭니다. `fixtures/`의 프로젝트는 손으로 작성합니다. 공개된 프로젝트라도 유출된 키가 들어 있을 수 있으니 실제 프로젝트의 파일을 복사하지 않습니다.
- 비밀 값은 마스킹해서만 내보냅니다. 탐지 결과, 수정 프롬프트, 리포트에는 마스킹한 값만 담고 원문은 담지 않습니다.
- 쉬운 설명이 필요합니다. 사용자는 보안 전문가가 아닙니다. 사용자에게 보이는 문구는 모두 영어와 한국어로 상대적으로 간단해야 합니다. Rust에서는 `LocalizedText`, 웹 UI에서는 `web/src/messages.ts`를 사용하며, 한국어 문구는 기존 문구처럼 "~해요" 말투로 씁니다.

## 개발 환경

| 도구       | 버전                                                                       |
|------------|----------------------------------------------------------------------------|
| Rust       | 1.99.1(clippy, rustfmt 포함). rustup이 `rust-toolchain.toml`을 읽어 설치함 |
| Node.js    | 22.12 이상                                                                 |
| pnpm       | 11.20.0. `package.json`의 `packageManager`에 지정되어 있음                 |
| cargo-deny | Rust 의존성을 바꿀 때 필요                                                 |

```bash
$ pnpm install
$ pnpm build
$ cargo build
$ cargo run -p seethru-cli -- scan fixtures/supabase-vite
```

Rust 크레이트보다 웹 UI를 먼저 빌드하세요. `crates/seethru-report/build.rs`가 `web/dist/app.js`와 `web/dist/app.css`를 바이너리에 넣고 CSP 해시로 고정합니다. 두 파일이 없으면 빌드는 경고만 남기고, 바이너리는 HTML 리포트를 만들지 못합니다.

`pnpm dev`를 실행하면 웹 UI만 따로 띄울 수 있습니다. `seethru scan --json`으로 만든 리포트를 열어 확인하세요.

## 검사

아직 CI가 없으니 Pull Request를 열기 전에 아래를 모두 직접 실행해 주세요. 하나도 빠짐없이 통과해야 합니다.

```bash
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo test --workspace
$ pnpm typecheck
$ pnpm test
```

Rust 의존성을 바꿨다면 `cargo deny check`도 실행하세요.

워크스페이스는 `unsafe`를 금지하고, 테스트를 포함한 모든 코드에서 `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `dbg!`를 막습니다. 대신 `Result`를 돌려주거나 `let ... else`를 쓰세요.

코드에는 주석이 거의 없습니다. 명확한 이름과 작은 함수로 뜻을 드러내고, 코드만 보고는 이유를 알 수 없을 때만 주석을 작성하세요. 물론 기존 코드베이스에 주석이 없는 것은 하나의 문제라고 볼 수도 있습니다. 주석을 추가하시고자 한다면 추가하셔도 괜찮습니다.

## 의존성

- 버전은 정확히 고정합니다. `Cargo.toml`에서는 `=1.2.3`처럼 씁니다. pnpm은 이미 정확한 버전으로 저장하도록 설정되어 있습니다.
- 공개된 지 14일이 지난 릴리스만 씁니다. 새로 들어오는 하위 의존성도 마찬가지입니다. pnpm은 `pnpm-workspace.yaml`의 `minimumReleaseAge`로 이를 강제합니다. Rust는 crates.io에서 공개일을 확인하고 `cargo update -p <크레이트> --precise <버전>`으로 더 오래된 릴리스에 고정하세요.
- 라이선스는 `deny.toml`의 허용 목록에 있어야 합니다.
- 의존성 트리는 작게 유지합니다. 필요 없는 기본 기능(default features)은 끄고, 새 의존성이 왜 필요한지 Pull Request에 적어 주세요.

## 리포트 스키마

`crates/seethru-core/src/report.rs`의 스캔 리포트는 웹 UI와 다른 도구가 읽는 형식입니다.

- 형태를 바꾸면 `crates/seethru-core/src/report.rs`와 `web/src/model.ts`의 `SCHEMA_VERSION`을 함께 올리고, `web/src/model.ts`의 파서도 고치세요.
- `cargo run -p seethru-cli -- schema > schema/scan-report.schema.json`으로 JSON Schema를 다시 만드세요. 잊으면 `committed_schema_matches_the_model` 테스트가 실패합니다.

## 규칙 추가하기

1. 변경 사항이 [안전 설계](README_KR.md#안전-설계)를 지키는지 확인합니다.
2. `crates/seethru-core/src/report.rs`의 `RuleId`에 항목을 추가하고, `as_str`에 kebab-case ID를 정합니다. 사용자가 이 ID를 `seethru.toml`에 적기 때문에, 한 번 릴리스한 ID는 바꾸지 않습니다.
3. `crates/seethru-analyzer/src/rules.rs`에 제목과 설명을 영어와 한국어로 쓰고, 테스트의 `every_text()`에 추가합니다. 이 테스트는 두 언어가 모두 있는지, 백틱으로 감싼 이름이 같은지 확인합니다.
4. 분석기에서 `Graph::add_finding`으로 탐지를 만듭니다. `[[accept]]`의 `path`가 맞출 수 있도록 위치를 꼭 넣습니다.
5. 심각도는 공격자가 할 수 있는 일을 기준으로 정합니다. `Info`는 저장소만으로 확인할 수 없는 경우에만 씁니다.
6. `crates/seethru-fix/src/lib.rs`에 수정 프롬프트를 영어와 한국어로 씁니다.
7. 코드 옆에 단위 테스트를, `crates/seethru-analyzer/tests`에 통합 테스트를 추가합니다. 프로젝트 전체가 필요한 규칙이면 픽스처를 추가하거나 늘립니다.
8. 스키마를 다시 만들고, `README.md`와 `README_KR.md`의 탐지 항목 표와 규칙 ID 표에 새 규칙을 넣습니다.

## 커밋과 Pull Request

- 커밋 메시지는 영어로 쓰고, 최근 `git log`의 형식을 따릅니다. 짧은 제목 줄로 시작하고, 설명이 더 필요하면 `-` 목록을 붙입니다.
- 커밋 하나에는 기능 하나만 담고, 관련 없는 변경은 나눕니다.
- `feat`, `chore` 같은 접두어를 붙이지 않습니다. 메시지에는 콜론, 마침표, 엠 대시, 가운뎃점을 쓰지 않습니다.
- Pull Request에는 무엇을 왜 바꿨는지와 실행한 검사를 적습니다. 새 규칙이라면 픽스처에서 어떤 탐지가 나오는지 보여 주세요.

## 보안 문제 신고

seethru 자체의 보안 문제는 공개 이슈가 아닌 상단 **Security** 탭의 **Report a vulnerability**로 비공개 신고해 주세요. 또는 <qtfelix@qu4nt.space>로 직접 연락주셔도 됩니다.

## 라이선스

기여한 내용은 프로젝트와 같은 [Apache License 2.0](LICENSE)으로 배포되는 데 동의한 것으로 봅니다.
