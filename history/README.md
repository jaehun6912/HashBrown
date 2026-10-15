# 개발 과정 소스

최종 버전([`src/`](../src/))에 이르기까지 단계별로 남긴 소스입니다. 학습 기록으로 보관한 코드이므로 최종 버전과 같은 보안 기능을 제공하지 않습니다. 각 단계는 프로토콜과 키 설정이 다르므로 **같은 단계의 서버와 클라이언트끼리** 실행해야 합니다.

| 단계 | 포트 | 키 파일 (실행 폴더 기준) | 주요 내용 |
| --- | --- | --- | --- |
| [01-socket](01-socket/) | 10101 | — | TCP 연결, 클라이언트 → 서버 메시지 전송 |
| [02-file-transfer](02-file-transfer/) | 12345 | — | `put`/`get` 명령으로 파일 송수신, 명령마다 재접속 |
| [03-eddsa](03-eddsa/) | 10101 | `server_private.pem`, `client_public.pem` / `client_private.pem`, `server_public.pem` | 파일명·크기·SHA-256에 Ed25519 서명, 검증 실패 시 저장 거부 |
| [04-eddsa-aes](04-eddsa-aes/) | 10101 | 03단계 키 + 양쪽 동일한 `aes_key.bin` (또는 `AES_KEY_FILE`) | 사전 공유 키로 AES-256-GCM 암호화, 파일 전체 + 해시에 서명 |

## 컴파일

Makefile은 최종 버전에만 있습니다. 과거 단계는 각 폴더에서 직접 컴파일합니다.

```bash
# 01
gcc -o socket_server socket_server.c && gcc -o socket_client socket_client.c
# 02
gcc -o server server.c && gcc -o client client.c
# 03
gcc -o server server.c eddsa.c -lcrypto && gcc -o client client.c eddsa.c -lcrypto
# 04
gcc -o server server.c eddsa.c aes.c -lcrypto && gcc -o client client.c eddsa.c aes.c -lcrypto
```

04단계 AES 키는 `openssl rand -out aes_key.bin 32`로 만들어 서버와 클라이언트 폴더에 같은 파일을 둡니다. 최종 버전은 이 파일을 사용하지 않습니다.

단계별 차이는 [구현 분석](../docs/ARCHITECTURE.md#단계별-변화와-발표-자료의-관계)을 참고하세요.
