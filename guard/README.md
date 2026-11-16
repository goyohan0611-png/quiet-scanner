# Quiet Guard · 서버 보호 도구 개발판

Quiet Scanner와 별도로 빌드하는 Rust 서버 프로그램이다. 상주 서비스·서명 검증·설치/제거·규칙 스냅샷 기반 위에 **SSH 로그인 방어와 Nginx 웹/API 요청 검사(WAF)를 연결하는 개발 단계**다. 아직 운영 서버에 바로 설치하는 완성 제품이 아니다. 노출 점검, 관리 화면과 사용자 알림은 후속 단계다. 실행 중이라는 이유로 보호 중으로 표시하지 않는다.

```sh
cargo test --manifest-path Cargo.toml --locked
cargo build --manifest-path Cargo.toml --release --locked
```

GUI·Tauri·Python 패킷 처리·Npcap에 의존하지 않는다. Ubuntu x86_64가 첫 설치 대상이다. Windows에서는 서명·정책·스냅샷 검증 도구를 시험할 수 있지만 Linux 상주 서비스를 실행하지 않는다.

## 서명된 설치 묶음

```sh
# 배포자의 안전한 서명 환경에서 실행. private.pem은 저장소에 넣지 않는다.
bash scripts/package.sh target/release/quiet-guard /새로운/배포폴더 1 0.1.0 /안전한/private.pem

# 사용자 서버: 공식 배포자에게 별도로 확인한 공개키를 사용한다.
sudo python3 scripts/deploy.py install --bundle /배포폴더 --trusted-key /신뢰한/release-public.pem
sudo quiet-guard status
sudo python3 scripts/deploy.py uninstall
```

최초 설치는 시스템 OpenSSL로 Ed25519 서명과 파일 해시를 확인한 **뒤에** 내려받은 프로그램을 실행한다. 검증하려는 프로그램 자신에게 최초 신뢰 검증을 맡기지 않는다. 묶음에 같이 들어 있는 임의 공개키를 믿어서는 안 된다. 현재 배포자 공개키는 `keys/release-public.pem`이며, 개인키는 저장소 밖의 로컬 전용 보관소에만 둔다. CI는 일회용 시험 키를 사용하고 제품 개인키를 받지 않는다.

설치는 관리자 권한이 필요하다. 상주 서비스는 systemd `DynamicUser`로 실행하며 루트 권한·네트워크 리스너를 갖지 않는다. 추후 보호 설정 변경은 별도의 제한된 관리 경로로 연결한다.

## SSH 방어 개발판

Ubuntu 24.04 x86_64와 실제 SSH 서버를 대상으로 한다. 먼저 위의 서명 검증 설치로 기반 서비스를 설치한다. 필요한 패키지를 준비하는 별도 개발용 절차는 다음과 같다. 기존 CrowdSec이 있으면 호환 버전을 확인하고 그 인스턴스의 설정과 서비스를 바꾸지 않는다.

```sh
sudo bash scripts/install_ssh_dependencies.sh

# 아래 관리 IP는 예시다. 실제 접속하는 관리자 PC의 출발지 IP로 바꾼다.
sudo --preserve-env=SSH_CONNECTION quiet-guard ssh enable --direct --management-ip 203.0.113.10 --port 22
sudo quiet-guard ssh status
quiet-guard status

sudo quiet-guard ssh allow 203.0.113.20
sudo quiet-guard ssh remove-allow 203.0.113.20
sudo quiet-guard ssh unblock 203.0.113.20
sudo quiet-guard ssh disable
sudo quiet-guard ssh enable
sudo quiet-guard ssh remove
```

`--direct`는 SSH 접속이 점프호스트·공유 프록시를 거치지 않는다는 운영자의 확인이다. 웹/CDN 경로의 확인과는 별개다. 최초 설정에는 실제 관리 IP가 필요하며, 전달된 `SSH_CONNECTION`의 접속자도 예외에 포함돼야 한다. 임의 웹 포트를 SSH 차단 대상으로 넣지 못하도록 `sshd -T`의 포트와 대조한다.

동작 흐름은 **SSH 로그인 실패 → journald → 고정된 CrowdSec 파서·시나리오 → 전용 로컬 API → Rust nftables 구성요소 → 설정한 TCP SSH 포트만 차단**이다. 공식 범용 방화벽 바운서를 그대로 연결하는 대신, 차단 범위를 SSH로 제한하는 구성요소를 별도로 작성했다. 공유 목록이나 외부 탐지 신호 연동은 이 단계에 포함하지 않는다.

- 전용 서비스는 `quiet-guard-ssh-engine.service`와 `quiet-guard-ssh-enforcer.service`다. 관리자 명령만 이를 설정한다. 평상시 상태 수집 에이전트는 계속 낮은 권한으로 실행한다.
- 전용 설정·자격 증명은 `/etc/quiet-guard/ssh`, 로컬 DB는 `/var/lib/quiet-guard/ssh`를 사용한다. API는 `127.0.0.1:17423`, 수집 상태 확인용 읽기 전용 지표는 `127.0.0.1:17424`를 사용하며 서비스의 외부 네트워크 연결도 제한한다.
- 기존 CrowdSec의 DB·API·수집 설정·규칙을 사용하거나 변경하지 않는다. 엔진 1.8.2와 출처·커밋·해시를 기록한 파서·패턴을 사용하며 기본 Hub 갱신이 이 규칙 복사본을 덮어쓰지 않는다.
- 관리자 IP, 루프백과 명시한 예외는 SSH 차단 집합에서 제외한다. CrowdSec 전체에 적용되는 전역 허용 목록은 만들지 않는다. `unblock`은 현재 결정을 해제하며, 새 공격이 계속되면 다시 탐지될 수 있다.
- API·서비스·소유 설정과 실제 방화벽 규칙·IP 집합을 주기적으로 확인한다. 확인 실패·설정 변경·30초 넘은 관측은 보호 확인으로 사용하지 않는다. 웹 방어가 아직 없으므로 SSH가 확인돼도 전체 상태는 `partially_protected`, 위험 점검은 `not_assessed`다.
- 정상 진단 문장을 journal에 넣고 실제 수집 카운터의 증가를 확인한다. 이 문장은 로그인 실패가 아니므로 공격 결정이나 차단을 만들지 않는다. API만 살아 있고 로그 읽기가 멈춘 경우도 확인 실패로 처리한다. 알 수 없는 차단 건수는 0건으로 표시하지 않으며, 상태 전환은 서비스 journal에 기록한다.
- 차단 결정은 로컬 DB에 보관하고 서비스를 부팅 시 시작하도록 등록한다. 커널 차단에는 최대 45초의 짧은 갱신형 만료를 둔다. 엔진·갱신이 멈추면 오래된 차단이 계속 남는 대신 만료되며, 이 구간을 정상 보호로 표시하지 않는다.
- OFF/제거는 소유한 SSH 전용 테이블·서비스만 정리한다. 사용자가 바꾼 설정은 덮어쓰거나 삭제하지 않는다. SSH 연결을 먼저 제거해야 기반 프로그램을 업데이트·제거할 수 있다. 제거한 사건 DB는 `/var/lib/quiet-guard/ssh-archive-*`의 관리자 전용 폴더에 보관한다. 재설정 시 옛 차단 결정을 복원하지 않는다.

`tests/test_ssh.sh`는 폐기 가능한 Linux VM에서 실제 실패 로그인, SSH TCP 접속 차단, 웹 포트 유지, 관리 IP·허용 예외·차단 해제, 서비스 재시작과 오류 상태, 외부 설정 보존을 검사한다. 서비스 재시작 시험을 실제 서버 재부팅 시험으로 간주하지 않는다. 전체 최초 설치·복구·관리 화면과 운영 환경 검증은 아직 남아 있다.

실제 TCP 통신 통합 시험은 IPv4로 수행한다. IPv6는 주소 처리와 방화벽 구조 검사를 포함하며 실제 IPv6 SSH 접속 조합은 추가 검증 대상이다.

서명·파일 크기·해시·정확한 파일 목록·대상 플랫폼을 검증한다. 설치된 공개키 변경, 같거나 낮은 배포 순번, 사용자가 수정한 설치 파일은 자동 덮어쓰기/삭제하지 않는다. 정상 명령 실패에 대한 롤백을 제공하며, 전원 차단·프로세스 강제 종료 도중의 복구 보장은 아직 구현하지 않았다. 자동 온라인 배포와 키 교체 절차도 후속 작업이다.

## 규칙 고정 실험

Hub의 `update`는 목록 갱신이고 `upgrade`는 설치 구성 갱신이다. 엔진이 과거 항목 버전을 직접 선택할 수 있다고 가정하지 않는다.

검증된 규칙·참조 데이터만 포함한 디렉터리에 manifest를 만들고 서명한다. `quiet-guard rules stage`는 복사본을 독립 디렉터리에 만든 뒤 다시 검증하며 기존 스냅샷을 덮어쓰지 않는다. **아직 운영 엔진을 이 스냅샷으로 전환하지 않는다.**

`tests/test_rules_snapshot.sh`는 폐기 가능한 Ubuntu VM에서 실제 CrowdSec이 분리된 규칙 경로를 읽는지, 원래 소스가 바뀌어도 스냅샷이 유지되는지 시험한다. API 자격 증명과 SQLite DB는 규칙 묶음에 넣지 않는다. 실험에서 파생한 설정 파일·자격 증명은 CI 임시 디렉터리에만 두며 배포하지 않는다.

규칙 배포 운영 초안:

- 정규 검증·묶음 제공은 주 1회 검토를 목표로 한다.
- 중대한 취약점은 24시간 안에 영향 평가를 시작하는 것을 목표로 하되, 개인 운영의 보장된 대응시간으로 홍보하지 않는다.
- 긴급 묶음도 서명·정상 요청·공격 요청·복구 시험을 생략하지 않는다.
- 설치 시 일일 유지보수의 실제 명령·타이머·cron을 조사한다. 전용 소유권이 확인된 작업만 조정하며 기존 CrowdSec의 자동 작업은 임의로 끄지 않는다.
- 규칙·데이터·설정이 바뀌면 이전 보호 검증 결과를 무효화한다. 규칙 고정은 최신 공격에 대한 자동 대응을 늦출 수 있으므로 상태에 묶음 날짜와 갱신 필요를 표시해야 한다.

## 정책과 다음 단계

`policy` 명령은 입력에 대한 결정을 보여주는 오프라인 도구이며 방화벽을 바꾸지 않는다. 웹 경로의 프록시 불확실성은 웹 IP 자동 차단만 보류한다. SSH는 자체 경로가 직접 접속이고 검증됐는지 독립적으로 판단한다. 점프호스트·VPN·공유 출발지가 있는 SSH를 무조건 직접 접속으로 가정하지 않는다.

CI는 Ubuntu 호스팅 VM에서 설치 수명주기를 시험한다. WAF 시험 클라이언트는 같은 시험 VM의 **별도 네트워크 공간과 veth 연결**을 사용해 웹 서버 루프백과 다른 출발지에서 요청한다. 실제 인터넷·CDN·물리적으로 별도 장치의 운영 경로 시험까지 대신하지는 않는다. 제품 운영 시에는 실제 외부 확인 장치를 구성해야 하며 그 장치 운영과 비용은 아직 자동화하지 않았다.

다음에는 앱·DB·관리 포트 직접 노출 점검, 관리 화면, 설치 흐름과 알림을 연결한다. 이 개발 브랜치는 기존 스캐너 릴리스와 분리하며, 자동 병합·제품 릴리스를 수행하지 않는다.

## 웹/API 요청 검사 개발판

첫 연결 대상은 Ubuntu 24.04 x86_64의 apt Nginx 1.24.0 계열이며 **CDN·로드밸런서가 없는 직접 접속** 구성이다. 웹 요청 한 건의 허용/차단만 수행한다. 웹 출발지 IP를 방화벽으로 자동 차단하지 않으므로 SSH 전용 차단과도 독립적이다. 앱의 인증·권한 검사나 DB 접근 제어를 대신하지 않는다.

동작은 **실제 Nginx 요청 → 고정한 공식 Lua 전달 모듈 → 전용 CrowdSec 1.8.2 AppSec/Coraza와 CRS → 실제 HTTP 응답** 순서다. Rust가 상태·외부 증거 유효기간·설정 세대·사건 기록을 판단하며, Nginx 설정 보존과 설치 조작은 포함된 제한된 Python 도우미가 수행한다. CrowdSec/Lua/CRS를 자체 제작 엔진으로 표현하지 않는다. 원본 커밋·파일 해시·로컬 수정 이유·라이선스는 `vendor/waf/upstream.json`과 포함된 라이선스 파일에 기록한다.

```sh
# CrowdSec 1.8.2를 먼저 준비한다. 기존 인스턴스는 호환 버전만 확인한다.
sudo bash scripts/install_ssh_dependencies.sh
sudo bash scripts/install_waf_dependencies.sh

# EXTERNAL_IP는 이 서버의 주소가 아닌 실제 별도 확인 장치의 출발지다.
sudo quiet-guard waf enable --direct --probe-peer EXTERNAL_IP --site https://service.example
sudo quiet-guard waf status
quiet-guard status

# /etc/quiet-guard/waf/probe-client.json을 외부 확인 장치로 안전하게 전달한다.
# 그 장치에서만 실행한다. 자격 증명 파일은 chmod 600을 유지한다.
python3 scripts/waf_probe.py /private/probe-client.json

sudo quiet-guard waf disable
sudo quiet-guard waf enable
sudo quiet-guard waf remove
```

`install_waf_dependencies.sh`는 Nginx Lua 모듈을 설치하며 패키지 설치가 기존 Nginx를 다시 불러올 수 있다. 이 개발 단계에서는 유지보수 시간에 명시적으로 실행한다. 전체 원클릭 설치와 외부 확인 장치 자동 배치는 아직 없다. `--allow-insecure-probe`는 격리된 HTTP 시험 전용이며 운영 진단 자격 증명 전송에는 HTTPS가 필요하다.

- 사이트 별칭·리스닝 포트·각 경로를 조사해 확인 대상을 만든다. 정확히 일치하는 경로와 단순 접두 경로만 지원하며 기존 Lua, real-IP 변경, 프록시 프로토콜, 정규식/중첩 location, rewrite·조건문, 403 오류 변환 같은 미검증 구성은 수정 전에 거부한다. 사용자가 `--direct`를 확인해도 프록시 존재를 완벽하게 증명할 수 없으므로 이 단계는 웹 IP 자동 차단을 제공하지 않는다.
- 각 경로에 외부 출발지의 정상 GET·정상 JSON POST·본문 차단 표식 POST와 실제 최종 응답이 모두 확인돼야 `verified`가 된다. 진단 요청은 앱에 전달하지 않는다. 기본 주기 60초, 유효시간 180초이며, Nginx 재시작/다시 읽기·엔진 재시작·사이트/규칙/패키지 변경 시 이전 증거를 재사용하지 않는다. 외부 장치가 없으면 `awaiting_external_check`로 남는다.
- 기본 오류 정책은 `passthrough`다. 엔진 장애 시 서비스 요청을 통과시키고 `unknown`/`degraded`로 표시한다. `--failure-action deny`를 명시하면 오류 응답을 사용한다. 상태 수집 주기는 10초, 수집 증거의 유효시간은 30초다. 두 서비스가 확인돼도 전체는 `partially_protected`, 위험은 계속 `not_assessed`다.
- 기본 본문 검사 한도는 1MiB다. 초과·압축·일부 HTTP/2 길이 없는 본문은 완전 검사로 세지 않는다. 기본은 헤더/URL 검사 후 통과하며 최근 180초의 불완전 검사를 별도 상태에 반영한다. `--body-action deny`는 이런 요청을 413으로 거부한다. HTTP/3은 첫 구성에서 지원하지 않는다. Nginx 자체 업로드 제한은 유지한다.
- 전용 설정/비밀값은 `/etc/quiet-guard/waf`의 관리자 전용 파일에, 코드만 `/usr/local/lib/quiet-guard/waf`에 둔다. LAPI·AppSec·지표는 각각 루프백 17425·17426·17427 포트다. 상태 수집용 Unix 소켓은 관리자만 접근할 수 있는 디렉터리에 두며 새 공개 관리 포트는 만들지 않는다. 전용 엔진의 외부 통신도 제한한다.
- 차단·검사 실패·불완전 검사 사건은 경로 식별자·출발지 IP·시각·결과만 기록한다. 요청 본문·URL 쿼리·인증 헤더는 Guard 사건 기록에 넣지 않는다. 공유 메모리의 최근 256건을 수집하고 관리자 전용 로그 두 파일(각 약 2MiB)로 제한한다. 이 범위를 넘는 폭주에서는 개별 사건이 유실될 수 있어 누락 수를 표시한다. 기존 사이트 자체의 접속 로그 정책을 바꾸지는 않는다.
- 초기 WAF 단계는 CrowdSec 공격 알림 생성을 끄고 자체 최소 사건 기록을 사용한다. 진단을 공격 결정·커뮤니티 공유로 보내지 않으며 CAPI/콘솔 공유는 연결하지 않는다. 상세 요청 분석·중앙 차단 목록·웹 IP 차단·완전한 감사 보관을 제공한다고 홍보하지 않는다.
- 변경 전 사이트 바이트·권한·소유 그룹과 해시를 보관한다. 정상 OFF는 추가한 검사 설정을 제거하고 원본 바이트를 복원한다. 운영자가 파일을 바꿨다면 자동 복원을 거부하고 변경 파일을 보존한다. 서명된 기반 프로그램 업데이트/제거는 SSH와 WAF를 먼저 제거해야 한다. 강제 종료·전원 차단 중 파일 교체의 자동 복구는 아직 후속 작업이다.

`tests/test_waf.sh`가 실제 Nginx와 검사 엔진을 연결해 정상 요청·공격 요청·외부 경로 증거·오류 통과·설정 보존을 검사한다. 시험 통과 범위와 운영 환경의 무오탐을 동일하게 보지 않는다. 실제 HTTPS·HTTP/2 조합, IPv6 웹 경로, 컨테이너 Nginx와 CDN 조합, 재부팅/업그레이드 중 복구는 추가 검증 대상이다.
