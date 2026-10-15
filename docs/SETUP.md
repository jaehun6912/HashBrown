# 최종 버전 실행 안내

아래 명령은 저장소 루트에서 시작하는 Linux/WSL Bash 기준입니다. 최종 버전은 `aes_key.bin`을 사용하지 않습니다.

## 1. 빌드 및 작업 폴더

```bash
make -C src
mkdir -p runtime/server/clients runtime/server/Files runtime/client/Files
cp src/build/server runtime/server/
cp src/build/client runtime/client/
```

## 2. 시연용 Ed25519 키 생성

처음 구성하는 빈 작업 폴더에서 한 번 실행합니다. 기존 키가 있는 환경에서는 아래 생성 명령으로 키를 덮어쓰지 마세요.

```bash
umask 077
openssl genpkey -algorithm ed25519 -out runtime/server/server_private.pem
openssl pkey -in runtime/server/server_private.pem -pubout -out runtime/client/server_public.pem
openssl genpkey -algorithm ed25519 -out runtime/client/client_private.pem
openssl pkey -in runtime/client/client_private.pem -pubout -out runtime/server/clients/pc1.pem
printf 'Hello, secure file transfer!\n' > runtime/client/Files/hello.txt
```

```text
runtime/
├── server/
│   ├── server
│   ├── server_private.pem
│   ├── clients/pc1.pem          # 클라이언트 공개키
│   └── Files/
└── client/
    ├── client
    ├── client_private.pem
    ├── server_public.pem
    └── Files/hello.txt
```

개인키는 해당 장치에만 보관합니다. 실제 장치를 나누어 실행할 때는 각 장치에서 자신의 개인키를 생성하고, 서버 공개키는 클라이언트로, 클라이언트 공개키는 서버의 `clients/<이름>.pem`으로 전달합니다. 공개키의 출처를 별도 신뢰할 수 있는 경로로 확인해야 합니다.

## 3. 실행

터미널 A (저장소 루트에서):

```bash
cd runtime/server
./server
```

터미널 B (저장소 루트에서):

```bash
cd runtime/client
./client
```

서버 주소에 `127.0.0.1`, 포트에 `10101`을 입력합니다. `1` → 파일 번호로 업로드하고 `3`으로 서버 목록을 확인합니다. `2` → 파일 번호로 다운로드합니다. 같은 이름의 파일이 있으면 검증 성공 후 교체되므로 시연용 파일을 사용하세요. `0`으로 클라이언트를 종료하고 서버는 `Ctrl+C`로 종료합니다.

서로 다른 장치에서는 서버 IPv4 주소를 입력하고 서버의 TCP 10101 포트에 접근할 수 있어야 합니다. 서버는 모든 IPv4 인터페이스에 바인딩됩니다. 서버 포트를 변경하려면 `src/server.c`의 `PORT`를 수정하고 다시 빌드합니다.

## 다중 클라이언트

클라이언트마다 별도 작업 폴더와 개인키를 사용하고 각 공개키를 서버 `clients/`에 다른 이름으로 등록합니다. 등록 이름은 `.pem`을 제외한 파일명입니다. 접속 시 디렉터리를 다시 읽으므로 새 등록은 다음 접속에 반영됩니다.

파일 저장소는 모든 등록 클라이언트가 공유합니다. 사용자별 저장소 격리나 파일 접근 권한 정책은 구현되어 있지 않습니다.

## 문제 해결

- 키 파일 열기 실패: 실행한 작업 폴더와 PEM 파일명을 확인합니다.
- 키 교환 실패: 서버 공개키와 서버 개인키의 짝, 클라이언트 개인키와 등록 공개키의 짝을 확인합니다.
- 연결 실패: 서버 실행 여부, IPv4 주소, 포트, 네트워크 연결을 확인합니다.
- 업로드 목록이 비어 있음: 클라이언트 작업 폴더의 `Files/`에 파일을 넣습니다.
- 구조체 크기 정적 검사 실패: 해당 ABI에서는 현재 전송 구조체 형식을 지원하지 않습니다. 정적 검사를 제거하여 우회하지 마세요.

키, 전송 파일, 실행 바이너리, `runtime/`은 `.gitignore`로 제외됩니다.
