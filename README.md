# GasChanger Field Diagnostics

GasChanger 장비의 현장 RTT 조회와 서명된 Fault 심볼 분석 도구입니다. 원본 펌웨어,
ELF, HEX, BIN, MAP 및 펌웨어 소스는 이 저장소에 포함하지 않습니다.

## 공개 내용

- `app/`: 조회 전용 RTT 터미널
- `symbols/`: Build ID별 최소 함수 주소 패키지와 Ed25519 서명
- `app/trusted_symbol_public.pem`: 심볼 서명 검증 공개키

`.gcsym`에는 HW/FW/Build ID와 함수 주소 범위 및 함수명만 포함합니다. 기계어,
전역 데이터, 문자열, 로컬 변수, 자료형, 소스 경로와 private Git 정보는 없습니다.

## 요구 사항

- Windows 10/11
- Python 3.10 이상
- STM32CubeIDE와 ST-LINK
- OpenSSL (`Git for Windows`에 포함된 OpenSSL도 자동 검색)
- RTT 콘솔이 포함된 GasChanger FW

## 실행

PowerShell에서 다음을 실행합니다.

```powershell
.\app\start_rtt_terminal.ps1
```

도구는 장비의 Build ID를 조회하고, 일치하는 `.gcsym`과 `.sig`를 이 저장소에서
다운로드하여 `%LOCALAPPDATA%\GasChanger\symbols`에 캐시합니다. 서명과 실행 FW,
Fault 기록 및 심볼 패키지의 Build ID가 모두 일치할 때만 PC/LR을 함수명으로
변환합니다.

조회 후 종료:

```powershell
.\app\start_rtt_terminal.ps1 -Command version,fault,watchdog
```

로그 저장:

```powershell
.\app\start_rtt_terminal.ps1 -LogPath .\rtt-session.log
```

OpenOCD는 `127.0.0.1`에만 RTT 포트를 열며 GDB/TCL/Telnet과 reset/halt/program/Flash
명령을 사용하지 않습니다. 도구 사용 조건은 [LICENSE.md](LICENSE.md)를 확인하십시오.

## 현재 공개 심볼

| HW | FW | Build ID |
|---|---|---|
| Rev3 | 3.1.1 | `b5f22a93c79e433b841437dc48b7c1fb` |
