# ALEPH T08 — Passkey Portfolio

기존 공개 소개 페이지에 패스키 등록·로그인과 본인만 조회하는 비공개 영역을 추가했다.
공개정보는 이메일·GitHub 주소·전공·학력이다. 비공개 항목 3개는 서버 DB에서 로그인한 소유자별로 조회한다.

## 실행

- Node.js 24
- npm install --ignore-scripts
- npm test
- npm run verify:card5 (가상 계정으로 로컬 요청·응답 검사)
- npm run build
- npm run dev (공개 화면·로컬 API 확인용)

실제 패스키 등록·로그인은 https://alepht08passkeyportfolio.vercel.app 에서 진행한다.
Vercel 환경변수는 SUPABASE_URL, SUPABASE_SECRET_KEY를 사용한다. T08_ORIGIN이 없으면 정식 주소를 기본값으로 사용한다.
기존 설정을 유지하면 되며 추가 환경변수는 없다. 서버 전용 키는 브라우저·소스·로그에 넣지 않는다.

## 구현 문서

- docs/CARD1.md: 카드 1 당시의 공개·비공개 경계 기록
- docs/CARD2.md: 패스키 등록 구현 기록
- docs/CARD3.md: 로그인·서버 세션·비공개 조회·로그아웃과 검사 범위
- docs/CARD4.md: 같은 계정 패스키 추가·삭제·마지막 키 보호와 검사 범위
- docs/CARD5.md: 계정 격리, 인증 구현 설명서 6항목, 실제 제출 증거 수집 순서
- docs/card5-local-evidence.json: 로컬 시뮬레이션 요청·응답 (실제 배포 증거가 아님)
- docs/card5-db-evidence.json: 실제 DB 롤백 검사 결과 (기기 인증 검사가 아님)

## 저장 구조

기존 t08_users, t08_challenges, t08_passkeys에 카드 3의 t08_auth_challenges, t08_sessions, t08_private_items를 추가했다.
테이블은 서버 전용 접근과 RLS를 사용한다. 세션 토큰 원문 대신 해시만 저장한다.
로그아웃은 DB의 세션을 폐기한다. 비공개 조회 시마다 만료·폐기를 검사한다.
DB 변경은 이미 적용했다. docs/card2-schema.sql, docs/card3-schema.sql, docs/card4-schema.sql을 같은 DB에 재실행하지 않는다.

## 검증 범위

자동 테스트 32개와 실제 DB 트랜잭션·권한 검사를 통과했다. 카드5 전용 로컬 보고서는 11개 요청 검사를 담는다. 자동 검사의 암호 검증기는 모킹되어 있으며, 실제 기기 로그인 검사를 대체하지 않는다.
사용자는 실제 등록·로그인·두 패스키 관리와 삭제된 키 거절·남은 키 로그인 동작을 확인했다. 휴대폰 인증 완료 후 오류 안내가 남는 현상은 미해결이다. 실제 두 계정의 서로 다른 가상 본문·성공/거절 요청 증거 수집은 아직 필요하다.
비공개 본문은 아직 비어 있다. 본문 편집은 현재 범위에 포함하지 않는다. 로그인 후 패스키 추가·삭제가 가능하며 마지막 키는 삭제를 차단한다. 삭제 후 남은 키로 다시 로그인해야 한다.
라이브러리는 @simplewebauthn/server 14.0.3을 고정 사용한다. 현재 작업 환경의 npm 접근 제한으로 lockfile 생성은 미완료다.

## 비공개 조회 API

GET/HEAD /api/private-info는 로그인 세션 소유자의 항목만 반환한다.
같은 Origin의 POST /api/private-info도 조회 전용이며 JSON 본문을 파싱한 뒤 본문의 userId 등을 버리고 세션 소유자만 사용한다.
주소의 userId/user_id/owner_id가 상대 계정을 가리키면 403이다. 비로그인·만료·폐기된 세션은 401이다.
자료 생성·편집 API는 추가하지 않았다. 테스트 계정 자료는 로컬 또는 ROLLBACK되는 DB 트랜잭션 안에서만 만들었다.

## 제출 상태

카드5 구현과 자동/DB 검사는 완료했지만 실제 배포의 모든 제출 증거까지 완료된 것은 아니다.
별도 패스키 계정 2개의 실제 요청·응답, 질문 재사용/옛 쿠키 재전송 등의 마스킹 기록이 남아 있다.
C12의 실제 개인정보 없음 조건과 기존 공개 연락처 유지 결정의 충돌도 docs/CARD5.md에 명시했다.
검증용 비공개 내용은 모두 가상이며 실제 비공개 본문은 채우지 않았다.
