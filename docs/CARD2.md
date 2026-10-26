# T08 카드 2 — 패스키 등록

## 반영 위치

- Supabase ALEPH_Task(gywwtgecjkfmgnwkbmzl)에 t08_users, t08_challenges, t08_passkeys와 t08_finish_registration 함수를 생성했다.
- 카드 2 코드를 T08 저장소에 반영한다. Vercel 자동 배포 상태와 실제 기기 등록 결과는 별도로 확인한다.
- 이전의 비공개 정보 API는 계속 401로 잠겨 있다. 등록 완료는 비공개 자료 접근 권한을 부여하지 않는다.

## 구현한 흐름

1. 이름·저장 위치를 입력하고 패스키 등록을 누른다.
2. 서버가 임의 사용자 ID와 32바이트 브라우저 바인딩 값을 생성한다. SimpleWebAuthn이 일회용 질문을 생성한다.
3. 질문·브라우저 바인딩 값의 SHA-256·후보 사용자 ID·이름·저장 위치를 DB에 5분간 보관한다.
4. 브라우저는 navigator.credentials.create()로 패스키를 만든다. residentKey와 userVerification을 required로 요구한다.
5. 서버는 SimpleWebAuthn verifyRegistrationResponse()로 DB의 질문, 고정 Origin·RP ID, 사용자 확인 여부를 검증한다.
6. 검증이 성공한 경우에만 DB 함수로 사용자·공개키를 저장하고 질문을 사용 완료 처리한다. 함수의 행 잠금과 트랜잭션으로 중복 요청을 차단한다.
7. 등록 직후 15분 동안 HttpOnly 쿠키로 해당 사용자의 패스키 이름·등록 날짜·저장 위치 목록만 조회할 수 있다. 이 쿠키는 로그인 쿠키가 아니다.

현재는 첫 번째 패스키 등록만 지원한다. 같은 계정에 두 번째 패스키 추가, 삭제, 로그인·로그아웃은 이후 카드에서 구현한다.
브라우저에 등록 완료 쿠키가 없는 상태에서 시작하는 첫 등록은 새 계정을 만든다. 기존 계정에 패스키를 추가하는 기능으로 사용하지 않는다.
등록 직후의 목록 조회 기간이 끝나면 로그인 기능이 연결될 때까지 기존 목록을 다시 열 수 없다.

## API

- POST /api/passkeys?action=options : 새 등록 질문 생성
- POST /api/passkeys?action=verify : 등록 응답 검증 및 저장
- POST /api/passkeys?action=cancel : 사용 전 질문 삭제
- GET /api/passkeys?action=list : 등록 직후 해당 사용자 목록 조회

변경 요청은 고정 Origin과 일치해야 한다. 질문은 같은 브라우저의 HttpOnly/Secure/SameSite=Strict 쿠키에 묶인다.
클라이언트가 넘긴 userId를 소유자로 사용하지 않는다. 소유자 ID는 서버의 질문 레코드에서 가져온다.
DB REST 접근은 서버 전용 키를 사용하며 키나 상위 서버의 오류 본문을 응답·로그로 출력하지 않는다.
테이블 3개는 RLS를 켰고 PUBLIC/anon/authenticated 권한을 제거했다. service_role만 접근한다.
RLS 정책이 없는 것은 공개·일반 로그인 역할을 전부 막기 위한 의도적인 설정이다.
저장 위치는 사용자가 직접 적은 값이다. 사이트가 Google/Apple/Windows 저장소를 자동 판별했다고 주장하지 않는다.

## 취소와 실패

- 기기 창을 취소하면 cancel API로 질문을 삭제한다. 사용자·패스키는 아직 생성되지 않은 상태다.
- 네트워크가 끊겨 취소 요청이 전달되지 않으면 질문이 DB에 남을 수 있으며 5분 뒤 더 이상 사용할 수 없다. 화면에 정리 여부 미확인이라고 표시한다.
- 검증 실패는 사용자·패스키를 저장하지 않는다.
- DB 저장까지 성공한 직후 응답을 잃은 경우 목록을 다시 조회하여 등록 여부를 확인한다.
- 잘못된 바인딩·만료·재사용·다른 Origin의 요청은 거절한다.

## 필요한 Vercel 환경변수

| 이름 | 값 |
| --- | --- |
| SUPABASE_URL | https://gywwtgecjkfmgnwkbmzl.supabase.co |
| SUPABASE_SECRET_KEY | 해당 프로젝트의 서버 전용 secret key 또는 기존 service_role 키 |
| T08_ORIGIN | https://alepht08passkeyportfolio.vercel.app |

키는 Vercel 환경변수 입력란에서 설정하며 GitHub·HTML·JS·문서·채팅에 붙이지 않는다.
DB 설정은 이미 적용되었으므로 card2-schema.sql을 같은 DB에 다시 실행하지 않는다.

## 의존성·실행

- Node.js 24
- @simplewebauthn/server 14.0.3을 정확한 버전으로 지정했다.
- 이 작업 환경에서는 npm registry가 403으로 차단되어 라이브러리를 다운로드하지 못했다.
- 이전 카드의 의존성 없는 package-lock.json을 재사용하지 않았다. 설치 가능한 환경에서 npm install --ignore-scripts 후 생성되는 package-lock.json을 함께 검토해야 한다.
- 의존성 설치·lockfile 생성·실제 검증 라이브러리 실행이 끝나기 전에는 배포 준비 완료로 판정하지 않는다.
- npm test는 애플리케이션 흐름을 테스트한다. 카드 2 테스트의 WebAuthn 검증기는 명시적으로 모킹되어 있다.
- 실제 기기 등록은 고정 HTTPS Origin에서 검사해야 한다. http://127.0.0.1 로컬 서버만으로 실제 패스키 검증을 통과시키지 않는다.

공식 참고:
- https://simplewebauthn.dev/docs/packages/server
- https://github.com/MasterKale/SimpleWebAuthn/releases/tag/v14.0.3
- https://supabase.com/docs/guides/database/postgres/row-level-security

## 검사 결과와 남은 증거

- Node 자동 검사 10개 통과: 카드 1 비노출/차단, 질문 고유성, 성공 후 재사용 차단 흐름, 취소, 다른 브라우저 차단, 만료, 검증 실패, Origin, 입력값, 목록 접근 검사.
- 실제 DB에서 service_role로 등록 저장·질문 사용 완료·재사용 거절·취소 처리를 트랜잭션 안에서 검사하고 전부 ROLLBACK했다. 실제 기기나 WebAuthn 서명 검증 증거는 아니다.
- 실제 DB 권한 확인: 3개 테이블 모두 RLS=true, anon/authenticated SELECT=false; DB 함수 SECURITY INVOKER, 일반 역할 실행 불가.
- 검사 후 사용자/패스키/질문 레코드는 모두 0개다. 가짜 성공 등록 자료를 남기지 않았다.
- 실제 기기 등록, 등록 요청 2회의 서로 다른 질문, DB 공개키, 취소 후 DB 건수, 실제 저장 관리자 확인은 아직 검사하지 않았다.
- 그러므로 카드 2를 최종 PASS로 선언하지 않는다.

## 카드 2 통과 기준 대응

| ID | 준비한 내용 | 현재 상태 |
| --- | --- | --- |
| C19 | 서버 생성 질문 DB 보관 | 코드 준비·DB 구조 적용, 실제 기기 흐름 미확인 |
| C20 | 요청마다 질문 값 상이 | 자동 흐름 검사 통과, 실제 요청 기록 필요 |
| C21 | 등록 후 공개키 저장 | DB 저장 함수 검사 통과, 실제 공개키 증거 필요 |
| C22 | 공개키이며 비밀번호가 아님 | public_key 컬럼과 설명 준비 |
| C23 | 개인키 미전송 | 네이티브 WebAuthn 응답만 전송, 실제 Network 확인 필요 |
| C24 | 패스키 이름 | 입력·DB 저장·목록 코드 준비 |
| C25 | 취소 시 등록 자료 미생성 | 자동/DB 검사 통과, 실제 기기 취소 검사 필요 |
| C26 | 저장 위치 기록 | 사용자 입력란·목록 준비, 실제 관리자 확인 필요 |
