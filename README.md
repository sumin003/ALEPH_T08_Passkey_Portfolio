# ALEPH T08 — Passkey Portfolio

기존 공개 소개 페이지에 패스키 등록·로그인과 본인만 조회하는 비공개 영역을 추가했다.
공개정보는 이메일·GitHub 주소·전공·학력이다. 비공개 항목 3개는 서버 DB에서 로그인한 소유자별로 조회한다.

## 실행

- Node.js 24
- npm install --ignore-scripts
- npm test
- npm run build
- npm run dev (공개 화면·로컬 API 확인용)

실제 패스키 등록·로그인은 https://alepht08passkeyportfolio.vercel.app 에서 진행한다.
Vercel 환경변수는 SUPABASE_URL, SUPABASE_SECRET_KEY를 사용한다. T08_ORIGIN이 없으면 정식 주소를 기본값으로 사용한다.
기존 설정을 유지하면 되며 추가 환경변수는 없다. 서버 전용 키는 브라우저·소스·로그에 넣지 않는다.

## 구현 문서

- docs/CARD1.md: 카드 1 당시의 공개·비공개 경계 기록
- docs/CARD2.md: 패스키 등록 구현 기록
- docs/CARD3.md: 현재 로그인·서버 세션·비공개 조회·로그아웃과 검사 범위

## 저장 구조

기존 t08_users, t08_challenges, t08_passkeys에 카드 3의 t08_auth_challenges, t08_sessions, t08_private_items를 추가했다.
테이블은 서버 전용 접근과 RLS를 사용한다. 세션 토큰 원문 대신 해시만 저장한다.
로그아웃은 DB의 세션을 폐기한다. 비공개 조회 시마다 만료·폐기를 검사한다.
DB 변경은 이미 적용했다. docs/card2-schema.sql과 docs/card3-schema.sql을 같은 DB에 재실행하지 않는다.

## 검증 범위

자동 테스트 24개와 실제 DB 트랜잭션·권한 검사를 통과했다. 자동 검사의 암호 검증기는 모킹되어 있으며, 실제 기기 로그인 검사를 대체하지 않는다.
실제 등록은 사용자가 확인했으며, 카드 3의 실제 PIN 로그인과 제출용 성공·거절 증거는 배포 후 확인해야 한다.
비공개 본문은 아직 비어 있다. 편집·추가 패스키 등록·삭제는 현재 범위에 포함하지 않는다.
라이브러리는 @simplewebauthn/server 14.0.3을 고정 사용한다. 현재 작업 환경의 npm 접근 제한으로 lockfile 생성은 미완료다.
