<!-- border-opencode-command -->
Drive the border fail-closed push gate through the `border` tool.

User request: $ARGUMENTS

Interpret the request as ONE `border` CLI invocation: the first word is the
command (`check`, `push`, `status`, `llm-request`, `llm-ingest`, `scan`,
`roundtrip`, or `--help`) and the rest are argv tokens. Call the `border` tool
with `command` set to the first word and `extra` set to the remaining tokens,
then report the CLI exit code (0 pass / 1 gate-blocked or partial push / 2 gate
could not answer) and the relevant lines of its output. If no request was given,
call the tool with `command: "--help"` and summarize the command list from it.
`push --yes` is refused by the tool — a real push is the human gate and belongs
to a terminal: if the user asks for one, tell them to run `border push --yes`
there. A bare `border push` through the tool is a DRY-RUN by the CLI's own
contract: it reports the verdict the gate would produce without touching any
remote.
