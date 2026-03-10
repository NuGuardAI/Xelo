# Demo eval gap plan

Date: 2026-03-10

Primary repo: `https://github.com/Uma-Ramanathan-1/rag-chatbot-demo`

Fixtures:

- `tests/test_toolbox/fixtures/rag-chatbot-demo`
- `tests/test_toolbox/fixtures/cookbooks`
- `tests/test_toolbox/fixtures/langchain-azure`
- `tests/test_toolbox/fixtures/langchainjs-create-agent`
- `tests/test_toolbox/fixtures/langchainjs-multi-agent`

## Cross-adapter rule

Every extraction fix below should be implemented as a paired change across Xelo's language adapters unless the pattern is truly language-specific.

- Python side: update the relevant logic under `src/xelo/adapters/python/*`, shared Python adapters, and any Python-side framework/tool/prompt/datastore detectors they depend on.
- JS/TS side: make the equivalent update under `src/xelo/adapters/typescript/*` plus any shared TS/JS framework or prompt/tool handling that feeds those adapters.
- Shared logic: if the issue belongs in language-agnostic ranking, verification, gap-fill, or normalization, update the shared layer in `src/xelo/core/*` as well, but do not use that as a substitute for missing parser support in one language.

Adapter parity checklist for every fix:

1. Add or update the Python regression fixture/assertion.
2. Add or update the JS/TS regression fixture/assertion.
3. Verify the fix does not only improve one adapter while leaving the equivalent pattern broken in the other.

## Eval summary

- Regex-only: precision `0.25`, recall `0.2727`, F1 `0.2609` (`TP=3`, `FP=9`, `FN=8`)
- LLM enabled with Gemini (`vertex_ai/gemini-3.1-flash-lite-preview`): precision `0.25`, recall `0.2727`, F1 `0.2609` (`TP=3`, `FP=9`, `FN=8`)
- LLM delta: none

## Why LLM did not help

- The Gemini-backed LLM path was operational for this run.
- Gap-fill ran for `TOOL` but discovered `0` new nodes, so it added no recall.
- Verification did run and rejected some weak candidates, but none of the rejected nodes changed benchmark scoring enough to move the final metrics.
- The run hit the LLM budget ceiling (`budget_exceeded=True`) after verification, but the earlier gap is still deterministic: the missing assets are not being surfaced as plausible candidates in the first place.

## Key accuracy gaps

1. Datastore recall is `0%`.
   Root cause: datastore extraction collapses multiple concrete FAISS stores into one generic `faiss` node instead of recovering the assigned store/index identity.
   Evidence:
   - Missed `docs_index`, `tickets_index`, `configs_index`, `chat_history_index`
   - Extracted only `faiss @ backend/app/chains.py:26`

2. Prompt recall is `0%`.
   Root cause: prompt extraction records generic prompt names (`System Prompt`, `generic`) instead of assignment-aware symbols like `retrieval_prompt`, `fallback_prompt`, and `prompt`/persona prompt variables.
   Evidence:
   - Missed `retrieval_prompt`, `fallback_prompt`, `persona_chat_prompt`
   - Extracted `System Prompt @ backend/app/main.py:149` and `generic @ backend/app/chains.py:94`

3. Auth detection has the right type but the wrong file/path.
   Root cause: auth heuristics prefer generic config mentions in `data-generators/config.yaml` over real credential reads like `OPENAI_API_KEY = os.getenv(...)` in backend runtime code.
   Evidence:
   - Missed `AUTH generic @ backend/app/config.py:60`
   - False positive `AUTH generic @ data-generators/config.yaml:25`

4. Comment/example parsing creates a model false positive.
   Root cause: model extraction is reading commented migration examples and turning `llama3:8b` into a live `MODEL 8b`.
   Evidence:
   - False positive `MODEL 8b @ backend/app/main.py:137`

5. Privilege extraction is noisy on synthetic content generators.
   Root cause: privilege heuristics are firing on generated example content and broad filesystem/network terms inside the data generator domain files, not on executable privileged behavior in the chatbot runtime.
   Evidence:
   - False positives: `filesystem_write`, `network_out`, `rbac`

## Fix plan

1. Improve FAISS datastore naming.
   - Extend the Python datastore adapter to capture assignment targets around `FAISS.load_local(...)`, `FAISS.from_texts(...)`, and `.save_local(...)`.
   - Add the equivalent JS/TS datastore naming logic for vector-store constructors and store assignments so Xelo does not fix Python-only datastore identity while leaving JS/TS store names generic.
   - When a FAISS store is loaded from a path constant like `DOCS_INDEX_PATH`, resolve the constant and emit a concrete datastore name such as `docs_index` instead of generic `faiss`.
   - Add a fixture regression test using `rag-chatbot-demo` to assert all four stores are recovered.

2. Make prompt extraction assignment-aware.
   - In the prompt adapter, preserve the left-hand variable name when extracting `ChatPromptTemplate.from_messages(...)`.
   - Mirror the same behavior in the TS/JS prompt adapter for `systemPrompt`, imported prompt constants, and multiline template-string prompt definitions.
   - Prefer symbol names over generic labels like `System Prompt`.
   - Add prompt-name normalization so `prompt` in `chains.py` can map to a more stable canonical form when multiple prompts exist in the same file.

3. Tighten auth ranking.
   - Prioritize executable env access patterns such as `os.getenv("OPENAI_API_KEY")`, `load_dotenv`, and framework config objects over YAML key names in generator configs.
   - Down-rank auth detections from non-runtime folders like `data-generators/` unless there is supporting runtime usage.

4. Ignore commented example models.
   - Strip or down-rank commented-out code before model extraction.
   - Apply the same comment/example filtering to TS/JS model extraction so commented model names and sample output blocks do not become nodes there either.
   - Add a regression test that ensures `llama3:8b` in comments does not emit `MODEL 8b`.

5. Reduce privilege false positives from synthetic text emitters.
   - Exclude data-generation content blocks where privilege keywords appear inside generated prose/templates rather than API calls.
   - Require stronger executable evidence for `filesystem_write`, `network_out`, and `rbac` in Python files.

6. Restore a real LLM benchmark path.
   - Gemini is now working through `AISBOM_LLM_MODEL=vertex_ai/gemini-3.1-flash-lite-preview` plus `GEMINI_API_KEY`.
   - Keep this path for future comparisons, but focus engineering effort on deterministic extraction first because LLM currently has no leverage on the missed assets in this repo.

## Expected impact after fixes

- Biggest gain should come from deterministic extraction, not LLM.
- Recovering 4 datastores and 3 prompts while removing 3 to 5 obvious false positives would move this fixture materially upward even before LLM is restored.
- The LLM path should be treated as a secondary cleanup/recall pass after the extractor stops collapsing names and reading comments.

---

## langchain-ai/cookbooks

Repo: `https://github.com/langchain-ai/cookbooks`

Fixture scope: `python/langgraph/agents/assistants-demo`

## Eval summary

- Regex-only: precision `0.8333`, recall `0.4545`, F1 `0.5882` (`TP=5`, `FP=1`, `FN=6`)
- LLM enabled with Gemini (`vertex_ai/gemini-3.1-flash-lite-preview`): precision `0.8750`, recall `0.6364`, F1 `0.7368` (`TP=7`, `FP=1`, `FN=4`)
- LLM delta: `+14.86` F1, `+2` true positives, no additional false positives

## Why LLM helped only partially

- Gemini gap-fill was active and discovered four tool candidates.
- After verification, the fixture improved from `TP=5` to `TP=7`, which indicates the LLM path can recover some tool coverage for this repo.
- The remaining misses were still deterministic structural gaps: `supervisor_graph`, `supervisor_system_prompt`, and two tools (`finance_research`, `advanced_research_tool`) remained undetected.
- The run hit the token budget (`budget_exceeded=True`), which likely limited how much post-gap verification could complete.

## Key accuracy gaps

1. Tool recall is `0%`.
   Root cause: the deterministic extractor does not recognize LangChain `@tool`-decorated async functions in this demo, even though the tool names are also enumerated in config lists.
   Evidence:
   - Missed `finance_research`, `advanced_research_tool`, `basic_research_tool`, `get_todays_date`
   - Regex-only emitted no tool nodes from `src/react_agent/tools.py`
   - Gemini recovered only part of this set, so deterministic tool extraction is still the real fix

2. Supervisor agent recall is incomplete.
   Root cause: agent extraction catches `create_react_agent(...)` but misses `create_supervisor(...)` graphs and the compiled supervisor returned from `make_supervisor_graph`.
   Evidence:
   - Missed `supervisor_graph @ src/supervisor/supervisor_prebuilt.py:19`
   - Found only `graph @ src/react_agent/graph.py:29`

3. Prompt naming is still generic for inline string prompts.
   Root cause: prompt extraction labels the no-config prompt as `Make Graph` instead of using the assigned variable name or higher-signal semantic name, and it misses the supervisor prompt entirely.
   Evidence:
   - False positive `Make Graph @ src/react_agent/graph_without_config.py:10`
   - Missed `supervisor_system_prompt @ src/supervisor/supervisor_configuration.py:12`

## Fix plan

1. Add first-class support for LangChain `@tool` detection.
   - Extend the Python tool adapter to emit tool nodes from `@tool`-decorated functions, including async defs.
   - Add the equivalent TS/JS support for `tool(...)` constructor patterns and decorator-like wrappers so tool recovery stays aligned across both adapters.
   - Preserve the function name as the tool name and ignore helper wrappers like `get_tools`.
   - Add a regression fixture assertion using `cookbooks` to require all four tools from `src/react_agent/tools.py`.
   - This should remove the repo's current dependence on LLM gap-fill for tool recovery.

2. Detect LangGraph supervisor graphs.
   - Extend Python agent extraction to recognize `create_supervisor(...)` the same way it recognizes `create_react_agent(...)`.
   - Add the equivalent graph-constructor parity on the TS/JS side for `createAgent(...)`, graph builders, and other orchestration constructors so agent-object assignment handling stays consistent across languages.
   - When a variable assigned from `create_supervisor(...)` is later compiled and returned, emit the graph variable name (`supervisor_graph`) as the canonical agent identity.

3. Improve prompt extraction for assigned string prompts.
   - For multiline string assignments like `prompt = """..."""`, prefer the variable name over fallback labels.
   - Apply the same logic to config-style fields such as `supervisor_system_prompt` in Pydantic models.
   - Apply the equivalent logic to TS/JS `systemPrompt`, template strings, and imported prompt constants.

4. Restore a real LLM benchmark path.
   - Gemini is now working for this fixture and should stay as the benchmark LLM path.
   - Increase or tune the LLM budget only after deterministic tool extraction lands; otherwise the eval spends budget recovering assets the parser should already know how to emit.

## Expected impact after fixes

- This fixture should improve mainly through deterministic tool and agent extraction.
- Recovering 4 tools plus the supervisor graph would move recall from `45%` to near-complete with no precision penalty if prompt naming is also tightened.
- The current LLM path is not the bottleneck here; the missing `@tool` and `create_supervisor(...)` support is.

---

## langchain-ai/langchain-azure

Repo: `https://github.com/langchain-ai/langchain-azure`

Fixture scope: `samples/react-agent-docintelligence`

## Eval summary

- Regex-only: precision `0.6000`, recall `0.4286`, F1 `0.5000` (`TP=3`, `FP=2`, `FN=4`)
- LLM enabled with Gemini (`vertex_ai/gemini-3.1-flash-lite-preview`): precision `0.6000`, recall `0.4286`, F1 `0.5000` (`TP=3`, `FP=2`, `FN=4`)
- LLM delta: none

## Why LLM did not help

- Gemini gap-fill was active and proposed new prompt- and deployment-like candidates.
- It generated candidates such as `Analyst Prompt`, `Parser Prompt`, and `Azure AI Foundry Agent Service`, but these did not survive verification into benchmark-matching assets.
- The run hit the LLM budget (`budget_exceeded=True`), but the larger issue is structural: the deterministic extractor is not surfacing the actual prompt and tool symbols that the benchmark expects.

## Key accuracy gaps

1. Tool recall is `0%`.
   Root cause: the extractor emits a synthetic wrapper tool (`tools_89`) from `ToolNode(tools)` instead of the real tool instance `AzureAIDocumentIntelligenceTool`.
   Evidence:
   - False positive `TOOL tools_89 @ src/react_agent/graph.py:89`
   - Missed `AzureAIDocumentIntelligenceTool @ src/react_agent/graph.py:24`

2. Prompt recall is `0%`.
   Root cause: prompt extraction does not follow imported prompt constants into `src/react_agent/prompts.py`, so both canonical prompts are missed.
   Evidence:
   - Missed `PARSER_PROMPT @ src/react_agent/prompts.py:3`
   - Missed `ANALYST_PROMPT @ src/react_agent/prompts.py:14`
   - Gemini generated generic prompt labels, but not the exact assigned identifiers

3. Graph-level agent extraction is incomplete.
   Root cause: the extractor finds the internal nodes (`parser`, `analyst`) but misses the compiled graph object as the top-level agent and misclassifies the bridging function as an agent.
   Evidence:
   - Missed `document_intake_graph @ src/react_agent/graph.py:101`
   - False positive `AGENT prepare_analysis @ src/react_agent/graph.py:64`

## Fix plan

1. Prefer concrete tool constructors over `ToolNode(...)` wrappers.
   - In Python, when a `ToolNode(tools)` wrapper is encountered, resolve the underlying `tools` collection and emit the tool class names rather than a synthetic wrapper name.
   - In JS/TS, do the equivalent for arrays passed into graph/tool wrappers so wrapper nodes do not replace the underlying named tools.
   - Add a regression assertion requiring `AzureAIDocumentIntelligenceTool` for this fixture.

2. Support imported prompt constant resolution.
   - Extend Python prompt extraction to trace imported symbols like `from react_agent.prompts import ANALYST_PROMPT, PARSER_PROMPT`.
   - Extend TS/JS prompt extraction to trace imported prompt constants from sibling modules and preserve the exported identifier names.
   - When those symbols point to multiline constant strings, emit the constant names as prompt assets.

3. Distinguish orchestration helpers from real agents.
   - Do not emit plain bridging/helper functions like `prepare_analysis` as agents unless they create or return an agent object.
   - Recognize `builder.compile(...).with_config(...)` assignments as graph-level agents and preserve the assigned variable name (`graph`) or compiled graph identity (`document-intake-agent`).
   - Mirror that distinction in TS/JS graph builders so helper functions, routers, and state reducers do not become agents unless they wrap agent execution.

4. Keep Gemini as the validation path, not the primary fix.
   - Gemini is useful for checking whether hidden prompt/tool evidence exists, but it is not enough here because the generated candidate names do not match the source-level identifiers.
   - Deterministic extraction of imported prompts and wrapped tools should be fixed before tuning LLM budget.

## Expected impact after fixes

- Recovering the real Azure tool, both prompts, and the compiled graph agent would move this fixture from `F1=0.50` to a much healthier baseline without depending on LLM.
- Precision should also improve by removing the wrapper/tool-node and helper-function false positives.

---

## langchain-ai/langchainjs createAgent samples

Repo: `https://github.com/langchain-ai/langchainjs`

Fixture scope:

- `examples/src/createAgent/tools.ts`
- `examples/src/createAgent/customSystemPrompts.ts`

## Eval summary

- Regex-only: precision `0.8000`, recall `0.3636`, F1 `0.5000` (`TP=4`, `FP=1`, `FN=7`)
- LLM enabled with Gemini (`vertex_ai/gemini-3.1-flash-lite-preview`): precision `0.8571`, recall `0.5455`, F1 `0.6667` (`TP=6`, `FP=1`, `FN=5`)
- LLM delta: `+16.67` F1, `+2` true positives, no additional false positives

## Why LLM helped only partially

- Gemini gap-fill successfully recovered concrete tool names (`get_user_info`, `save_user_info`, `check_account`) and the `InMemoryStore` datastore candidate.
- Final scoring improved because the recovered tool names matched the ground truth.
- The remaining misses are deterministic: all agent objects created via `createAgent(...)` were still not emitted as agents, and `InMemoryStore` still failed to survive into a matching datastore in the final discovered set.
- The run hit the token budget (`budget_exceeded=True`), but the missing agent detection is the main blocker.

## Key accuracy gaps

1. Agent recall is `0%`.
   Root cause: the TypeScript extractor does not emit `createAgent({...})` assignments as agent assets in these examples.
   Evidence:
   - Missed `user_info_agent`, `customerServiceAgent`, `contextAwareAgent`
   - No agent nodes were emitted from either `createAgent/*.ts` file

2. Tool recall depends too heavily on LLM gap-fill.
   Root cause: deterministic TS tool extraction is missing `tool(...)` constructor patterns even when the tool name is explicitly set in the config object.
   Evidence:
   - Regex-only missed `get_user_info`, `save_user_info`, `check_account`
   - Gemini recovered those names, which confirms the source contains enough direct evidence

3. Datastore extraction is incomplete for JS runtime stores.
   Root cause: `new InMemoryStore()` is not being emitted reliably as a datastore asset.
   Evidence:
   - Ground truth expects `InMemoryStore @ createAgent/tools.ts:39`
   - Gemini proposed it during gap-fill, but it still did not score as a true positive in the final output

4. Prompt naming is generic on plain message literals.
   Root cause: prompt extraction mistakes invocation payloads like `messages: "..."` for prompt assets and emits `Messages` instead of assignment-aware prompt names.
   Evidence:
   - False positive `PROMPT: Messages @ createAgent/tools.ts`

## Fix plan

1. Add TypeScript `createAgent(...)` assignment detection.
   - Emit the left-hand variable name as an `AGENT` when a TS/JS variable is assigned from `createAgent(...)`.
   - Add a regression assertion for `user_info_agent`, `customerServiceAgent`, and `contextAwareAgent`.
   - Add the equivalent parity check on Python graph/agent factory assignments so future agent-constructor fixes do not diverge across languages.

2. Add deterministic TS tool-constructor support.
   - Recognize `const x = tool(async ..., { name: "..." })` and prefer the explicit `name` field.
   - This should remove the current dependence on Gemini for basic tool recovery.
   - Keep Python `@tool` / tool-factory support in sync with the same canonical-name rules.

3. Improve JS datastore detection.
   - Treat `new InMemoryStore()` and similar LangGraph store constructors as datastores.
   - Preserve the class name instead of requiring a storage API call later in the file.
   - Keep Python in-memory/vector-store constructor handling aligned so store-constructor naming semantics are consistent across adapters.

4. Tighten prompt extraction for JS message payloads.
   - Do not convert plain `messages:` invocation strings into prompt assets unless they are part of an actual prompt definition.
   - Prefer `systemPrompt` assignments and middleware-returned system prompt strings over transient invoke payloads.
   - Apply the same false-positive guard to Python transient message payloads and call-site string literals.

## Expected impact after fixes

- Deterministic TS support should make this fixture much less dependent on LLM and move it toward high recall quickly.
- The best wins are agent extraction and first-pass tool extraction.

---

## langchain-ai/langchainjs multi-agent samples

Repo: `https://github.com/langchain-ai/langchainjs`

Fixture scope:

- `examples/src/multi-agent/handoffs.ts`
- `examples/src/multi-agent/router-knowledge-base.ts`

## Eval summary

- Regex-only: precision `0.8000`, recall `0.3636`, F1 `0.5000` (`TP=4`, `FP=1`, `FN=7`)
- LLM enabled with Gemini (`vertex_ai/gemini-3.1-flash-lite-preview`): precision `0.8000`, recall `0.3636`, F1 `0.5000` (`TP=4`, `FP=1`, `FN=7`)
- LLM delta: none

## Why LLM did not help

- Gemini gap-fill generated generic candidates like `Notion Search Tool`, `Slack Search Tool`, and `Agent Handoff Tool`, plus a `LangGraph MemorySaver` datastore.
- Those candidates did not map to the source-level identifiers in ground truth, so benchmark scoring did not improve.
- The remaining misses are structural: explicit tool names and `createAgent(...)` agent assignments are still not being surfaced deterministically.

## Key accuracy gaps

1. Tool recall is `0%`.
   Root cause: the TS extractor misses both `tool(...)`-defined handoff tools and the wrapper knowledge-base tool.
   Evidence:
   - Missed `transfer_to_sales`, `transfer_to_support`, `search_knowledge_base`
   - Gemini only recovered generic semantic labels, not the code identifiers

2. Agent naming is partial.
   Root cause: the extractor identifies graph builders like `builder` and `workflow`, but not the underlying `createAgent(...)` assignments for `salesAgent` and `supportAgent`.
   Evidence:
   - Found `builder` and `workflow`
   - Missed `salesAgent` and `supportAgent`

3. Spurious auth detection remains in TS examples.
   Root cause: auth heuristics fire on documentation text or auth-related string literals inside the router sample even though there is no auth component in this fixture.
   Evidence:
   - False positive `AUTH: generic @ multi-agent/router-knowledge-base.ts`

## Fix plan

1. Reuse the TS `tool(...)` and `createAgent(...)` fixes from the createAgent fixture.
   - They should directly recover `transfer_to_sales`, `transfer_to_support`, `search_knowledge_base`, `salesAgent`, and `supportAgent`.
   - Keep the equivalent Python tool/agent naming rules aligned so multi-agent examples in both languages converge on the same canonical naming behavior.

2. Make LLM verification stricter on generic TS tool labels.
   - Reject semantic labels that do not anchor to explicit source identifiers when the code contains named `tool(...)` objects.

3. Tighten TS auth extraction.
   - Avoid auth classification from incidental example text unless there is a concrete auth library, credential field, or auth API usage in code.
   - Apply the same stricter requirement to Python auth extraction so auth heuristics do not drift between adapters.

## Expected impact after fixes

- This fixture should improve primarily through deterministic TS parsing, not LLM.
- Once explicit `tool(...)` and `createAgent(...)` support is in place, both recall and precision should rise materially.
