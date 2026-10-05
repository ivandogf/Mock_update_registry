# Mock Update Registry

Учебный моковый реестр обновлений ПО для демонстрации безопасного обновления по шаблону А.10 ГОСТ Р 72118—2025.

Проект моделирует полный путь:

```text
publish → download → verify → install → rollback
```

Работа демонстрируется через Swagger FastAPI. Реестр хранит опубликованные подписанные пакеты, устройство получает их через Gateway, проверяет и устанавливает локальную копию. При ошибке установки выполняется автоматический откат.

## Возможности

- Создание продуктов, публикация пакетов и просмотр истории версий.
- Формирование manifest, вычисление SHA-256 и подпись Ed25519.
- Проверка подписи через заранее доверенный открытый ключ.
- Проверка совместимости `target` и актуальности версии через `packaging.version.Version`.
- Раздельные серверные и локальные указатели `current/fallback`.
- Временное хранилище с правилами доступа для Downloader, Verifier и Installer.
- Имитация установки и откат с использованием доверенных локальных копий.
- Аудит этапов обновления и отказов в доступе.
- Четыре учебных сценария ошибок.

## Технологии

- Python 3.11 или новее.
- FastAPI и Pydantic.
- Локальный PostgreSQL, SQLAlchemy 2 с AsyncSession и asyncpg.
- Alembic для миграций.
- cryptography для Ed25519, hashlib для SHA-256.
- python-dotenv для загрузки `.env`.
- pytest и httpx для тестов.

## Настройка окружения

Команды ниже предназначены для PowerShell. Выполняйте их из корня проекта: пути к файлам и каталогам хранения заданы относительно него.

### 1. Установить зависимости

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

### 2. Настроить PostgreSQL

PostgreSQL должен быть запущен локально. Создайте базу через pgAdmin или psql, если её ещё нет:

```sql
CREATE DATABASE mock_update_registry;
```

Создайте `.env` из примера, сохранив существующий файл, если он уже настроен:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

В `.env` используется только одна переменная:

```dotenv
DATABASE_URL=postgresql+asyncpg://USER:PASSWORD@localhost:5432/mock_update_registry
```

В `app/config.py` заданы обычные константы:

```python
STORAGE_ROOT = Path("storage")
SERVER_TRUSTED = True
```

### 3. Применить миграции

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
```

### 4. Подготовить доверенный открытый ключ

```powershell
.\.venv\Scripts\python.exe -m app.provision_key
```

Эта команда явно добавляет открытый ключ локального учебного подписанта в доверенное хранилище:

- закрытый ключ подписанта: `storage/server/signing_key.raw`;
- доверенный открытый ключ: `storage/trusted_keys/<signing_key_id>.pub`.

Если ключ подписанта ещё не создан, команда создаст его. Повторное добавление того же открытого ключа допустимо.

Для добавления заранее доверенного открытого ключа из файла доступен параметр `--public-key`:

```powershell
.\.venv\Scripts\python.exe -m app.provision_key --public-key .\trusted-public-key.pub
```

Файл должен содержать открытый Ed25519-ключ в формате raw, 32 байта. Verifier использует только доверенные открытые ключи. `signing_key_id` выбирает ключ из этого хранилища; получение пакета не добавляет новые доверенные ключи.

## Запуск

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

- Swagger: <http://127.0.0.1:8000/docs>.
- Проверка запуска: `GET /health`, ответ `{"status":"ok"}`.

## Учебные роли

На маршрутах с зависимостью `get_role()` используется HTTP-заголовок `Role`:

- `Role: publisher` — создание продукта, публикация и чтение пакетов, запуск обновлений.
- `Role: device` — чтение пакетов и запуск обновлений/сценариев.

Если заголовок не указан, используется `device`. Неизвестное значение роли возвращает `403` и записывается как `ACCESS_DENIED`.

Для создания продукта и публикации пакета указывайте `publisher` в поле `Role` в Swagger.

## Проверка основного пути через Swagger

### 1. Создать продукт

Вызовите `POST /products` с `Role: publisher`:

```json
{
  "name": "demo-app",
  "target": "linux-x64"
}
```

Сохраните возвращённый `id` продукта.

### 2. Опубликовать первую версию

Вызовите `POST /products/{product_id}/packages`:

- `Role`: `publisher`;
- `version`: `1.0.0`;
- `file`: любой непустой учебный файл.

Максимальный размер файла — 16 МиБ. Версия должна соответствовать PEP 440 и быть строго новее текущей серверной версии этого продукта.

### 3. Создать устройство

Вызовите `POST /devices`, подставив UUID продукта вместо `<product_id>`:

```json
{
  "name": "test-device",
  "product_id": "<product_id>",
  "target": "linux-x64"
}
```

Сохраните `id` устройства. На новом устройстве `current_package_id` и `fallback_package_id` равны `null`.

### 4. Скачать и проверить пакет

Вызовите `POST /devices/{device_id}/updates/download`. В ответе:

- `state`: `VERIFYING`;
- `temporary_storage.state`: `SEALED`;
- `id`: идентификатор созданной сессии обновления.

Затем вызовите `POST /updates/{session_id}/verify`. При успехе:

- `verification_result`: `PASSED`;
- `temporary_storage.state`: `VERIFIED`;
- сессия остаётся в `VERIFYING`, ожидая установки.

### 5. Установить пакет

Вызовите `POST /updates/{session_id}/install`. При успехе:

- сессия получает `COMPLETED`;
- пакет сохраняется в `storage/devices/<device_id>/` и становится доверенным;
- `current_package_id` устройства указывает на установленный пакет;
- при первой установке `fallback_package_id` остаётся `null`;
- временные `.pkg` и `.meta` удаляются, заполняется `cleaned_at`.

### 6. Обновить устройство и выполнить rollback

Опубликуйте версию `2.0.0`, затем вызовите `POST /devices/{device_id}/updates/run`. Этот маршрут выполняет download → verify → install автоматически.

После успешной установки версии `2.0.0`:

- device `current` указывает на `2.0.0`;
- device `fallback` указывает на `1.0.0`.

Используйте `id` этой новой сессии для `POST /updates/{session_id}/rollback`. Устройство восстановит исходные указатели сессии: `current` станет `1.0.0`, `fallback` — `null`, а сессия получит `ROLLED_BACK`.

Rollback использует локальные доверенные копии и проверяет их SHA-256. Если исходная копия отсутствует, повреждена или не является доверенной, сессия получает `FAILED` с причиной в `failure_code`.

### 7. Посмотреть состояние и аудит

- `GET /devices/{device_id}` — текущее состояние устройства.
- `GET /updates/{session_id}` — результат сессии, временное хранилище и конфигурация сценария.
- `GET /updates/{session_id}/events` — последовательность событий с компонентом, уровнем, сообщением и `details`.

Обычная успешная установка включает события:

```text
UPDATE_CHECK_STARTED
UPDATE_FOUND
DOWNLOAD_STARTED
STORAGE_CREATED
DOWNLOAD_COMPLETED
STORAGE_SEALED
HASH_VALID
SIGNATURE_VALID
TARGET_VALID
VERSION_VALID
PACKAGE_VERIFIED
INSTALL_STARTED
DEVICE_CURRENT_UPDATED
INSTALL_COMPLETED
STORAGE_CLEANED
```

## Временное хранилище и current/fallback

Жизненный цикл данных во временном хранилище:

```text
WRITE → SEALED → VERIFIED
              ↘ REJECTED
```

- Downloader записывает данные и запечатывает хранилище только в `WRITE`.
- Verifier читает данные только в `SEALED`.
- Installer читает данные только в `VERIFIED`, после проверки разрешения на установку для сессии.
- Запрещённый доступ записывается как `ACCESS_DENIED`.

После завершения установки, отката или отказа Verifier временные файлы очищаются. Запись в БД сохраняет историю состояния и `cleaned_at`; новое обновление создаёт собственное хранилище в `WRITE`. Проверенный пакет, ожидающий установки, остаётся доступен Installer. Ошибка удаления файлов отражается событием `STORAGE_CLEANUP_FAILED` и не отменяет успешно завершённую установку.

Серверные и локальные указатели имеют разные назначения:

- `server_release_heads.current/fallback` — рекомендуемые сервером опубликованные версии.
- `device_state.current/fallback` — установленная и предыдущая локальные доверенные версии устройства.

Публикация новой версии изменяет серверные указатели. Указатели устройства меняются после успешной установки. Rollback восстанавливает `original_current_package_id` и `original_fallback_package_id` сессии. Неудачная установка не добавляет target в доверенные пакеты; ранее успешно установленная доверенная копия сохраняется.

## Учебные сценарии

Запуск:

```text
POST /devices/{device_id}/scenarios/{scenario_type}/run
```

В Swagger параметр `scenario_type` предлагает четыре значения:

1. **`CORRUPTED_PACKAGE`** — после загрузки изменяется один байт `.pkg`. Ожидается `HASH_INVALID → PACKAGE_REJECTED`.
2. **`INVALID_SIGNATURE`** — повреждается только подпись, файл и manifest сохраняются. Ожидается `HASH_VALID → SIGNATURE_INVALID → PACKAGE_REJECTED`.
3. **`OUTDATED_VERSION`** — загружается настоящий ранее опубликованный подписанный пакет с версией `<= current` устройства. Manifest не изменяется. Ожидается `HASH_VALID → SIGNATURE_VALID → TARGET_VALID → VERSION_INVALID → PACKAGE_REJECTED`. Если более старой версии нет, используется текущая версия и проверяется отказ при равенстве.
4. **`INSTALLATION_FAILURE`** — загрузка и проверка проходят успешно, затем операция сохранения пакета на устройстве выдаёт искусственную ошибку. UpdateManager запускает обычный rollback: `INSTALL_FAILED → ROLLBACK_STARTED → ROLLBACK_COMPLETED`, итог — `ROLLED_BACK`, если исходные локальные копии доступны и не повреждены.

Для `OUTDATED_VERSION` и `INSTALLATION_FAILURE` устройство должно уже иметь успешно установленный `current`. Для `INSTALLATION_FAILURE` также требуется опубликованная версия новее `current`. При невыполненных условиях маршрут возвращает `409` с пояснением.

После описанного выше ручного отката устройство имеет `current = 1.0.0`, а сервер — версию `2.0.0`: на этом устройстве можно запускать все четыре сценария.

Каждый запуск создаёт обычную сессию в `update_sessions`. В ней сохраняются `scenario_type` и `scenario_config`. `SCENARIO_STARTED` содержит название сценария, демонстрируемую защиту и описание внедрённой ошибки. Далее работают общие Verifier, Installer и UpdateManager. После завершения добавляется `STORAGE_CLEANED`.

## REST API

### Продукты и пакеты

- `POST /products` — создать продукт.
- `POST /products/{product_id}/packages` — опубликовать файл с версией.
- `GET /products/{product_id}/packages` — история опубликованных версий.
- `GET /products/{product_id}/latest` — текущий пакет сервера.
- `GET /packages/{package_id}/manifest` — manifest, подпись и `signing_key_id`.
- `GET /packages/{package_id}/content` — содержимое пакета.

### Устройства и обновления

- `POST /devices` — создать устройство.
- `GET /devices/{device_id}` — прочитать device `current/fallback`.
- `POST /devices/{device_id}/updates/download` — скачать и запечатать пакет.
- `POST /updates/{session_id}/verify` — проверить пакет.
- `POST /updates/{session_id}/install` — установить проверенный пакет.
- `POST /devices/{device_id}/updates/run` — выполнить нормальное обновление целиком.
- `POST /updates/{session_id}/rollback` — восстановить исходные указатели сессии.
- `GET /updates/{session_id}` — состояние и результат сессии.
- `GET /updates/{session_id}/events` — аудит сессии.
- `POST /devices/{device_id}/scenarios/{scenario_type}/run` — выполнить учебный сценарий.
- `GET /health` — проверка запуска приложения.

Результат проверки или установки содержится в `state`, `verification_result` и `failure_code`. Например, учебный отказ Verifier возвращает сессию в `REJECTED` с соответствующей причиной.

## Структура проекта

```text
app/
├── main.py                  # FastAPI и маршруты
├── config.py                # DATABASE_URL и константы
├── provision_key.py         # явное добавление доверенного public key
├── api/                     # REST API и Pydantic-схемы
├── db/                      # модели SQLAlchemy и AsyncSession
├── domain/                  # состояния, переходы и правила доступа
├── services/                # реестр, Gateway, Downloader, Verifier,
│                            # Installer, Rollback, UpdateManager, Monitor, сценарии
└── infrastructure/          # файлы, SHA-256, Ed25519, доверенные ключи
alembic/                     # миграции PostgreSQL
storage/
├── server/                  # опубликованные пакеты и учебный закрытый ключ
├── temporary/               # временные пакеты и metadata
├── devices/                 # локальные доверенные копии устройств
└── trusted_keys/            # заранее доверенные открытые ключи
tests/                      # автоматические тесты
```

## Таблицы БД

- `products` — продукты и их `target`.
- `packages` — версии, пути, SHA-256, точные байты manifest и подписи.
- `server_release_heads` — серверные `current/fallback` и время обновления указателей.
- `devices` — учебные устройства.
- `device_trusted_packages` — успешно установленные локальные доверенные копии.
- `device_state` — device `current/fallback`, ссылающиеся на доверенные копии этого устройства.
- `update_sessions` — состояния, исходные указатели, результаты и параметры сценариев.
- `temporary_storage` — состояние временного хранилища и отметки времени, включая очистку.
- `audit_events` — события и их `details`.

## Тесты

Для тестов должен быть доступен PostgreSQL из `DATABASE_URL`, с применёнными миграциями.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Тесты создают собственные продукты и устройства и удаляют свои записи после выполнения. Для проверки rollback устройство подготавливается обычными успешными установками. Проверяются целостность, подпись, target, версии, права доступа, установка, восстановление обоих исходных указателей, сценарии и очистка временных файлов.

## Упрощения относительно ГОСТ Р 72118—2025, шаблон А.10

Проект является учебным моковым реестром обновлений, поэтому часть требований шаблона А.10 реализована в упрощённом виде: реальный TLS и проверка сертификатов заменены логической проверкой доверия через `ExternalNetworkGateway`;

1. ВФС и драйверное разделение потоков данных не реализованы, доступ к хранилищам контролируется на уровне Python-сервисов;
2. установка обновления имитируется сохранением пакета в `storage/devices`, без реального обновления ОС или приложения;
3. rollback моделируется восстановлением `current/fallback` и использованием локальных доверенных копий;
4. `Monitor` реализован через `MonitorService` и `audit_events`;
5. `Role` — учебная модель авторизации;
6. закрытый Ed25519-ключ хранится локально, без HSM.
