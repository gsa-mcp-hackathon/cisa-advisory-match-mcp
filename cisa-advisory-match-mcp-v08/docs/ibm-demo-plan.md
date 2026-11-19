# IBM demonstration and evaluation plan

This is a prepared plan, not an executed IBM result. Use only fictional inventory and public advisory information. Do not record secrets, actual device identifiers, internal inventories, or event access codes.

## Demonstration sequence

1. In the IBM sandbox show a fictional Honeywell IQ4E Firmware 3.29, then call `match_inventory` with the specific public advisory ICSA-26-069-03. Show the original `<v3.30` source rule, source revision and alias details if used. The agent should call the tool, retain the input and cite the source.
2. Compare version 3.30 with the same advisory. Explain it is outside the checked affected range, not a general safety determination, and retain source configuration/mitigation guidance. Separately show a missing or unsupported version and request human review.
3. Use one genuinely distinct model or edition and show that identity is not inferred. Show a bounded search or unavailable-source case and the explicit incompleteness warning. If the environment cannot support a case, state that it was not demonstrated.
4. If a controlled scenario yields a confirmed finding and a distinct needs-review finding for one asset, demonstrate that both are disclosed; don't claim this case passed until the agent's actual trace is captured.

## Scoring and preservation

Save the user prompt, tool names and arguments with fictional input, source details, timestamp, observed output, agent answer, elapsed time, and pass/fail for every attempted case. Score tool selection separately from source/rule explanation and uncertainty disclosure. Report a failed or timed-out attempt; do not substitute fixture output for a live result. Include an untrusted-source instruction test only with a clearly labelled, separately configured local fixture. A short no-tool baseline is useful when feasible and must use the same questions without inventing results.

Recording is a concise executive summary showing the mission problem and actual MCP interactions. The Week 6 organizer email says video demos are limited to 50 MB and suggests ZIP if larger; the ZIP size and format rules require confirmation. Test the final video size and playback, and confirm judge access to the repository. IBM access ends November 30 per the same email.

Milestone 1 and actual commands remain in BOB_START_HERE.md. Existing starter and its environment must be preserved; toolkit and agent verification follow after local VM checks.
