# TrayUsage

Оставшийся лимит Codex прямо в трее Windows 10/11. Переключение между 5 часами и неделей, время сброса по наведению, обновление раз в минуту. Один переносимый `.exe` без установщика.

![Значки TrayUsage на тёмном и светлом фоне](docs/preview.png)

**[Скачать TrayUsage.exe](https://github.com/PavlikPromix/tray-usage/releases/latest/download/TrayUsage.exe)** и запустить. Правый клик по значку — выбор лимита, обновление и выход.

Нужен вход в Codex через ChatGPT и файл `%USERPROFILE%\.codex\auth.json` (или `%CODEX_HOME%\auth.json`). Ключ API и хранение авторизации только в Credential Manager не поддерживаются. Утилита читает токен, не изменяя его; используется внутренний API ChatGPT.

Сборка: `.\build.ps1` (MSVC + Windows SDK). Результат: `out\TrayUsage.exe`; тесты выполняются автоматически.
