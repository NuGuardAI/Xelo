"""Privilege-scoped detectors for AI SBOM extraction.

Replaces the single ``privilege_generic`` regex adapter with a set of
fine-grained detectors, one per privilege class.  Each emits a separate
PRIVILEGE node with a distinct ``canonical_name`` and ``privilege_scope``
so that downstream tools (policy engines, risk scorers) can reason about
*what* privileged capability an agent possesses.

Privilege classes
-----------------
``privilege:rbac``
    Role-based access control: permission checks, role assignment,
    ``@require_roles``, least-privilege declarations.

``privilege:admin``
    Administrative / superuser escalation: ``sudo``, ``is_superuser``,
    ``setuid``, ``runas``, ``elevate``.

``privilege:filesystem_write``
    Agents that can write, create, move, or delete files and directories.

``privilege:db_write``
    Agents that can execute SQL / ORM write operations (INSERT, UPDATE,
    DELETE, ``session.add``, ``Model.create``, etc.).

``privilege:email_out``
    Agents that can send emails via SMTP or transactional email APIs
    (SendGrid, SES, Mailgun, Resend, Postmark, etc.).

``privilege:social_media_out``
    Agents that can post to social platforms (Twitter/X, Reddit, Discord,
    Telegram, Slack, Instagram, etc.).

``privilege:code_execution``
    Agents that can run arbitrary shell commands or execute code
    (``subprocess``, ``os.system``, ``exec/eval``, sandbox tools).

``privilege:network_out``
    Agents that make outbound HTTP/WebSocket calls carrying data
    (``requests.post``, ``httpx.post``, webhooks, ``aiohttp``).
"""

from __future__ import annotations

import re

from ai_sbom.adapters.base import RegexAdapter
from ai_sbom.types import ComponentType

_CT = ComponentType.PRIVILEGE
_PRI = 150  # same priority bucket as the old generic adapter


def privilege_adapters() -> list[RegexAdapter]:
    """Return one ``RegexAdapter`` per privilege class."""
    return [
        # ------------------------------------------------------------------ #
        # RBAC / access-control declarations                                  #
        # ------------------------------------------------------------------ #
        RegexAdapter(
            name="privilege_rbac",
            component_type=_CT,
            priority=_PRI,
            patterns=(
                re.compile(
                    r"\b(rbac|role[_\-]based[_\-]access"
                    r"|least[_ ]privilege|privilege[_ ]escalation"
                    r"|access[_ ]control(?:[_ ]list)?"
                    r"|assign[_ ]role|check[_ ]permission|has[_ ]permission"
                    r"|require[_ ]permission|permission[_ ]required"
                    r"|@require_roles?|@roles_required"
                    r"|PermissionRequired|RBACMiddleware)\b",
                    re.IGNORECASE,
                ),
            ),
            canonical_name="privilege:rbac",
            metadata={"privilege_scope": "rbac"},
        ),

        # ------------------------------------------------------------------ #
        # Admin / superuser escalation                                         #
        # ------------------------------------------------------------------ #
        RegexAdapter(
            name="privilege_admin",
            component_type=_CT,
            priority=_PRI,
            patterns=(
                re.compile(
                    r"\b(sudo|superuser|is[_ ]superuser|is[_ ]staff|is[_ ]admin"
                    r"|run[_ ]as[_ ]root|runas|setuid|setgid|elevate[_ ]privilege"
                    r"|admin[_ ]required|@admin_required|require[_ ]admin"
                    r"|SudoCommand|AdminOnly|superuser[_ ]check)\b",
                    re.IGNORECASE,
                ),
            ),
            canonical_name="privilege:admin",
            metadata={"privilege_scope": "admin"},
        ),

        # ------------------------------------------------------------------ #
        # Filesystem write / modify / delete                                   #
        # ------------------------------------------------------------------ #
        RegexAdapter(
            name="privilege_filesystem_write",
            component_type=_CT,
            priority=_PRI,
            patterns=(
                # Explicit write-mode file opens  open("...", "w"|"a"|"wb"|"ab")
                re.compile(
                    r"""open\s*\([^)]*['"](w|a|wb|ab|w\+|a\+|wb\+|ab\+)['"]\s*\)""",
                    re.IGNORECASE,
                ),
                # pathlib / shutil / os write operations
                re.compile(
                    r"\b(write_text|write_bytes|write_text|os\.makedirs|os\.mkdir"
                    r"|os\.remove|os\.unlink|os\.rename|os\.replace"
                    r"|os\.chmod|os\.chown|os\.link|os\.symlink"
                    r"|shutil\.copy|shutil\.copy2|shutil\.move|shutil\.rmtree"
                    r"|shutil\.copytree|Path\.write_text|Path\.write_bytes"
                    r"|tempfile\.mkstemp|tempfile\.NamedTemporaryFile)\b",
                    re.IGNORECASE,
                ),
                # Agent tool class names for file operations
                re.compile(
                    r"\b(FileWriteTool|WriteFileTool|FileAppendTool|FileSaveTool"
                    r"|FileSystemTool|filesystem[_ ]tool|file[_ ]write[_ ]tool"
                    r"|DirectoryCreateTool|FileDeletionTool|file[_ ]delete[_ ]tool)\b",
                    re.IGNORECASE,
                ),
            ),
            canonical_name="privilege:filesystem_write",
            metadata={"privilege_scope": "filesystem_write"},
        ),

        # ------------------------------------------------------------------ #
        # Database write (SQL + ORM)                                           #
        # ------------------------------------------------------------------ #
        RegexAdapter(
            name="privilege_db_write",
            component_type=_CT,
            priority=_PRI,
            patterns=(
                # Raw SQL write statements
                re.compile(
                    r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM"
                    r"|CREATE\s+TABLE|DROP\s+TABLE|ALTER\s+TABLE"
                    r"|TRUNCATE\s+TABLE|REPLACE\s+INTO)\b",
                    re.IGNORECASE,
                ),
                # ORM / ODM write calls
                re.compile(
                    r"\b(session\.add|session\.delete|session\.merge"
                    r"|session\.execute.*UPDATE|session\.execute.*INSERT"
                    r"|db\.add|db\.delete|db\.session\.add"
                    r"|Model\.create|Model\.update|Model\.delete|Model\.save"
                    r"|\.save\(\)|\.create\(|\.update\(|\.delete\("
                    r"|\.bulk_create\(|\.bulk_update\(|\.bulk_delete\("
                    r"|collection\.insert|collection\.update_one|collection\.update_many"
                    r"|collection\.delete_one|collection\.delete_many|collection\.replace_one"
                    r"|table\.put_item|table\.update_item|table\.delete_item"
                    r"|client\.mutate\(|graphql_mutation)\b",
                    re.IGNORECASE,
                ),
            ),
            canonical_name="privilege:db_write",
            metadata={"privilege_scope": "db_write"},
        ),

        # ------------------------------------------------------------------ #
        # Outbound email                                                        #
        # ------------------------------------------------------------------ #
        RegexAdapter(
            name="privilege_email_out",
            component_type=_CT,
            priority=_PRI,
            patterns=(
                re.compile(
                    r"\b(smtplib|aiosmtplib|sendgrid|SendGridAPIClient"
                    r"|ses\.send_email|SESClient|boto3.*ses"
                    r"|mailgun|MailgunClient|resend|postmark|postmarker"
                    r"|yagmail|mailtrap|sparkpost|nylas"
                    r"|MIMEMultipart|MIMEText|email\.mime"
                    r"|send_mail\(|send_email\(|sendmail\("
                    r"|EmailMessage|smtplib\.SMTP|SMTP\.sendmail)\b",
                    re.IGNORECASE,
                ),
            ),
            canonical_name="privilege:email_out",
            metadata={"privilege_scope": "email_out"},
        ),

        # ------------------------------------------------------------------ #
        # Social media / messaging out                                          #
        # ------------------------------------------------------------------ #
        RegexAdapter(
            name="privilege_social_media_out",
            component_type=_CT,
            priority=_PRI,
            patterns=(
                re.compile(
                    # Twitter/X
                    r"\b(tweepy|twikit|twitter[_ ]api|TwitterClient"
                    r"|create_tweet|update_status|post_tweet)\b",
                    re.IGNORECASE,
                ),
                re.compile(
                    # Reddit
                    r"\b(praw|Reddit\(\)|subreddit\.submit|submission\.reply"
                    r"|reddit\.post|RedditClient)\b",
                    re.IGNORECASE,
                ),
                re.compile(
                    # Discord / Telegram / Slack send
                    r"\b(discord\.py|discord\.Client|bot\.send_message"
                    r"|channel\.send\(|ctx\.send\(|interaction\.respond"
                    r"|telegram\.Bot|python[_ ]telegram[_ ]bot|TelegramClient"
                    r"|telethon|bot\.send_photo|bot\.send_document"
                    r"|slack[_ ]sdk|WebClient\.chat_postMessage"
                    r"|slack[_ ]bolt|SlackClient\.send)\b",
                    re.IGNORECASE,
                ),
                re.compile(
                    # Instagram / LinkedIn / WhatsApp / Generic messaging
                    r"\b(instagrapi|instagram[_ ]client|linkedin[_ ]api"
                    r"|python[_ ]linkedin|whatsapp[_ ]api|twilio\.messages\.create"
                    r"|TwilioClient|vonage|nexmo|MessageBird)\b",
                    re.IGNORECASE,
                ),
            ),
            canonical_name="privilege:social_media_out",
            metadata={"privilege_scope": "social_media_out"},
        ),

        # ------------------------------------------------------------------ #
        # Code execution / shell access                                         #
        # ------------------------------------------------------------------ #
        RegexAdapter(
            name="privilege_code_execution",
            component_type=_CT,
            priority=_PRI,
            patterns=(
                # subprocess / os.system with actual execution
                re.compile(
                    r"\b(subprocess\.run|subprocess\.Popen|subprocess\.call"
                    r"|subprocess\.check_output|subprocess\.check_call"
                    r"|os\.system|os\.popen|os\.execv|os\.execle|os\.spawnl)\b",
                    re.IGNORECASE,
                ),
                # shell=True flag — explicit shell injection risk marker
                re.compile(r"\bshell\s*=\s*True\b"),
                # exec/eval used on dynamic strings (agent code-gen context)
                re.compile(
                    r"\b(exec\s*\([^)]*(?:code|script|source|generated|llm|response|output)"
                    r"|eval\s*\([^)]*(?:code|expr|generated|llm|response))\b",
                    re.IGNORECASE,
                ),
                # Sandboxed code-execution tool class names
                re.compile(
                    r"\b(BashTool|ShellTool|TerminalTool|CommandLineTool"
                    r"|E2BSandbox|E2BCodeInterpreter|e2b[_ ]code[_ ]interpreter"
                    r"|ModalSandbox|modal[_ ]sandbox|DaytonaSandbox"
                    r"|CodeInterpreterTool|code[_ ]interpreter[_ ]tool"
                    r"|PythonREPLTool|python[_ ]repl[_ ]tool|REPLTool)\b",
                    re.IGNORECASE,
                ),
            ),
            canonical_name="privilege:code_execution",
            metadata={"privilege_scope": "code_execution"},
        ),

        # ------------------------------------------------------------------ #
        # Outbound network / HTTP calls with data                              #
        # ------------------------------------------------------------------ #
        RegexAdapter(
            name="privilege_network_out",
            component_type=_CT,
            priority=_PRI,
            patterns=(
                # requests / httpx write-side methods
                re.compile(
                    r"\b(requests\.(post|put|patch|delete)\s*\("
                    r"|httpx\.(post|put|patch|delete)\s*\("
                    r"|aiohttp\.ClientSession\(\)\.post"
                    r"|urllib\.request\.urlopen\s*\("
                    r"|urllib3\.PoolManager\(\)\.request)",
                    re.IGNORECASE,
                ),
                # WebSocket / gRPC outbound
                re.compile(
                    r"\b(websocket\.send|websocket\.connect"
                    r"|grpc\.insecure_channel|grpc\.secure_channel"
                    r"|websockets\.connect|AsyncWebsocketClient)\b",
                    re.IGNORECASE,
                ),
                # Webhook dispatch helpers common in agent frameworks
                re.compile(
                    r"\b(dispatch_webhook|send_webhook|trigger_webhook"
                    r"|webhook[_ ]url|notify[_ ]external|outbound[_ ]request)\b",
                    re.IGNORECASE,
                ),
            ),
            canonical_name="privilege:network_out",
            metadata={"privilege_scope": "network_out"},
        ),
    ]
