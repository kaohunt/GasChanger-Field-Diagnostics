# GasChanger Field Diagnostics

GasChanger 장비의 현장 RTT 조회와 서명된 Fault 심볼 분석 도구입니다. 원본 펌웨어,
ELF, HEX, BIN, MAP 및 펌웨어 소스는 이 저장소에 포함하지 않습니다.

## 공개 내용

- `app/`: GUI 및 명령행 RTT 현장진단 도구
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
.\app\start_rtt_gui.ps1
```

GUI는 Dashboard, Live Watch 그래프/CSV, 전체 진단값, 이벤트, Fault 심볼 분석,
원시 콘솔과 세션 로그를 한 화면에서 제공합니다. 연결이 끊기거나 보드가 재부팅되면
자동으로 재접속합니다.

명령행 터미널을 사용하려면 다음을 실행합니다.

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

FW 3.1.2 이상에서 밸브, 부저, 램프, 통신 송신 및 MCU 재부팅 제어는 FW가 직접
Admin 암호를 검증한 뒤에만 활성화됩니다. 암호 원문은 공개 저장소, GUI 파일 및
세션 로그에 포함되지 않습니다. 밸브 제어 전에는 반드시 가스 공급계통이 안전한지
확인하십시오. 설정/교정값은 GUI에서 변경할 수 없습니다.

## 현재 공개 심볼

| HW | FW | Build ID |
|---|---|---|
| Rev3 | 3.1.3 | `557bf66319f84c31a8b9c58b9673b11f` |
| Rev3 | 3.1.2 | `387c24be579b4c3f8f3a8f633c92070c` |
| Rev3 | 3.1.1 | `b5f22a93c79e433b841437dc48b7c1fb` |
