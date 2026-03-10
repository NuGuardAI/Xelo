# Google Workshops eval gap plan

Date: 2026-03-10

Repo: `https://github.com/GoogleCloudPlatform/generative-ai/tree/main/workshops`

Fixture:

- `tests/test_toolbox/fixtures/google-generative-ai-workshops`

Scope:

- `workshops/ai-agents/ai_agents_for_engineers.ipynb`
- `workshops/rag-ops/1_prototyping_gemini.ipynb`
- `workshops/rag-ops/2.2_mvp_chunk_embeddings.ipynb`
- `workshops/rag-ops/2.3_mvp_rag.ipynb`
- `workshops/rag-ops/2.4_mvp_evaluation.ipynb`

## Cross-adapter rule

Every fix below should land with equivalent coverage across Xelo's Python and JS/TS stacks when the pattern is language-agnostic.

- Python side: update the notebook and framework handling under `src/xelo/extractor.py` and `src/xelo/adapters/python/*`.
- JS/TS side: apply the equivalent behavior under `src/xelo/adapters/typescript/*` when the same naming or ranking rule affects JS/TS repositories.
- Shared logic: put notebook preprocessing, ranking, dedup, and confidence fixes in shared code only when they are not parser-specific.

Parity checklist for each fix:

1. Add or update a Python regression.
2. Add or update a JS/TS regression if the same extraction rule exists there.
3. Verify the fix improves benchmark output without shifting noise into the other adapter stack.

## Eval summary

- Regex-only: precision `0.3333`, recall `0.2000`, F1 `0.2500` (`TP=2`, `FP=4`, `FN=8`)
- LLM enabled with Gemini (`vertex_ai/gemini-3.1-flash-lite-preview`): precision `0.3333`, recall `0.2000`, F1 `0.2500` (`TP=2`, `FP=4`, `FN=8`)
- LLM delta: none

## What matched

- `AUTH generic @ workshops/ai-agents/ai_agents_for_engineers.ipynb`
- `MODEL gemini-3-flash-preview` matched via synonym recovery from extracted `gemini-3`

## Why LLM did not help

- Gemini was operational and gap-fill ran.
- Gap-fill proposed notebook-adjacent noise (`Tavily` as a datastore, `Google Colab`, `Vertex AI Workbench` as deployments) instead of benchmark-matching assets.
- Verification accepted none of the new candidates (`verified_count=0`) and the run hit the LLM budget cap.
- The missing assets are mostly blocked by deterministic notebook parsing and adapter coverage, not by lack of an LLM pass.

## Key accuracy gaps

1. `ai-agents` notebook never reaches AST-based Python adapters.
   Root cause: notebook extraction leaves `%pip` shell/magic content in the synthesized Python source, so parsing fails before LangChain/LangGraph extraction runs.
   Evidence:
   - `AiSbomExtractor._extract_notebook_python(...)` output begins with invalid shell text from the install cell.
   - `xelo.ast_parser.parse(...)` returns `parse_error: invalid syntax (<unknown>, line 16)` for `ai_agents_for_engineers.ipynb`.
   - This suppresses recovery of `essay_workflow_graph`, `tavily_tool`, `outline_template`, and `writing_template`.

2. Notebook graph extraction misses compiled `StateGraph` agents.
   Root cause: even when notebook code parses, the current LangGraph extraction does not robustly name notebook-assembled graph objects from `builder = StateGraph(...)` followed by `graph = builder.compile(...)`.
   Evidence:
   - Missed `essay_workflow_graph` with synonym `graph`.
   - Only the framework node survives from `ai-agents`.

3. Tool extraction misses assigned tool instances in notebooks.
   Root cause: `tavily_tool = TavilySearchResults(...)` is a constructor-based tool assignment, not an `@tool` function or `ToolNode(...)`, and current extraction does not promote it to a `TOOL` node.
   Evidence:
   - Missed `tavily_tool @ workshops/ai-agents/ai_agents_for_engineers.ipynb:37`.
   - LLM gap-fill did not recover it.

4. Prompt extraction is not assignment-aware for notebook prompt variables.
   Root cause: prompt logic does not preserve notebook variable names for `ChatPromptTemplate.from_template(...)` and function-returned evaluation prompts, so prompt recall collapses to generic labels.
   Evidence:
   - Missed `outline_template`, `writing_template`, and `get_context_precision_prompt`.
   - Extracted only `PROMPT generic @ workshops/rag-ops/2.3_mvp_rag.ipynb`.

5. Datastore extraction misses Cloud Storage bucket identity.
   Root cause: the extractor does not treat `bucket = storage_client.bucket(BUCKET_NAME)` as a named datastore and does not resolve `BUCKET_NAME = "mlops-for-genai"`.
   Evidence:
   - Missed `DATASTORE mlops-for-genai`.
   - No datastore node was emitted from the `storage.Client(...)/bucket(...)` pattern.

6. Model attribution is path-local but semantically wrong in notebooks.
   Root cause: model detection anchors to later repeated mentions and client wrappers instead of the defining assignment or embedding constructor.
   Evidence:
   - `gemini-2.0-flash` was emitted from `2.4_mvp_evaluation.ipynb` instead of the earlier `1_prototyping_gemini.ipynb`.
   - False positive `MODEL google_client @ workshops/rag-ops/1_prototyping_gemini.ipynb`.
   - Missed `text-embedding-005` despite `TextEmbeddingModel.from_pretrained("text-embedding-005")`.

7. Notebook regex fallback still produces tutorial noise.
   Root cause: after AST misses, regex fallback over notebook JSON/tutorial text emits generic or incorrect nodes that do not correspond to executable assets.
   Evidence:
   - False positives: `PRIVILEGE code_execution`, `PROMPT generic`
   - LLM gap-fill added tutorial-environment concepts rather than repo assets

## Fix plan

1. Sanitize notebook source before parsing.
   - Update `src/xelo/extractor.py` notebook extraction to strip or comment out cell magics, shell escapes, and multiline `%pip` blocks before passing synthesized code to the Python AST parser.
   - Preserve executable Python cells and maintain stable line mapping as much as possible.
   - For Jupyter notebooks, feed only extracted code-cell content into regex fallback and LLM gap-fill/verification. Do not run those stages over raw notebook JSON, markdown cells, or output payloads.
   - Add the equivalent notebook-cell sanitization for JS/TS notebook parsing paths if notebook-backed JS/TS examples are supported or added later.
   - Add a regression test that `ai_agents_for_engineers.ipynb` parses without syntax error.

2. Improve LangGraph graph-object naming in notebook code.
   - Extend `src/xelo/adapters/python/langgraph.py` to treat `StateGraph(...)` plus `.compile(...)` assignment as a top-level `AGENT`.
   - Prefer the compiled variable name when available and normalize generic `graph` to a stable canonical name in benchmark fixtures through synonyms, not generic labels.
   - Mirror the same compiled-graph assignment handling in `src/xelo/adapters/typescript/*` for JS/TS orchestration builders.

3. Add constructor-based tool extraction.
   - In the Python adapter, emit `TOOL` nodes from assignments like `tavily_tool = TavilySearchResults(...)`.
   - Preserve the left-hand variable name and optionally include the class name as a synonym.
   - Add the equivalent JS/TS behavior for tool constructor assignments and imported tool classes.

4. Make notebook prompt extraction assignment-aware.
   - Preserve assigned names for `ChatPromptTemplate.from_template(...)`.
   - Capture named prompt-producing helper functions like `get_context_precision_prompt`.
   - Apply the same naming rule to TS/JS template-string and prompt-constructor patterns.

5. Add GCS bucket datastore detection.
   - Detect `storage.Client(...).bucket(...)` and resolve constant-backed bucket names like `BUCKET_NAME`.
   - Emit a named datastore node (`mlops-for-genai`) instead of nothing or a generic placeholder.
   - Add analogous constant-resolution behavior in the TS/JS datastore layer for cloud storage handles.

6. Tighten notebook model extraction and ranking.
   - Prefer model-definition assignments (`MODEL_ID = ...`, `TextEmbeddingModel.from_pretrained(...)`) over later repeated evaluation mentions.
   - Suppress client-wrapper names such as `google_client` when the real model identifier is available nearby.
   - Add equivalent ranking logic for JS/TS model constructors and config-backed model IDs.

7. Reduce notebook tutorial noise in regex and LLM stages.
   - Change notebook preprocessing so regex scanners and LLM gap-fill see code-cell source only.
   - Down-rank tutorial environment terms (`Colab`, notebook runtime setup, prose-only deployment mentions) unless supported by executable code.
   - Avoid emitting `code_execution` from notebook instructions/examples without direct execution APIs.
   - Make LLM verification stricter for notebook-derived candidates that are not tied to concrete symbols or assignments.

## Expected impact

- The biggest gain should come from notebook sanitization, because it unlocks the Python AST adapters for `ai-agents`.
- Once parsing is restored, this fixture should recover the missing graph, Tavily tool, and LangChain prompt templates without depending on Gemini.
- The remaining `rag-ops` misses should then be addressed by constant-aware datastore/model extraction and notebook-specific prompt naming, with LLM reserved as a secondary pass rather than the primary recovery path.
