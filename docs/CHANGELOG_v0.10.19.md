# NodeWatch v0.10.19 — Silver Peak connection fixes

Build: `2026-10-09-v0.10.19-sp-url`.

- **Pasted page addresses work:** the Orchestrator, Panorama and FortiGate URL fields now accept a pasted page
  address (e.g. `https://orch.example.com/9.4.11/webclient/html/swagger/index.html#/`) and reduce it to the server
  (`https://orch.example.com`), in the wizard and on save. Their APIs always live at the server root.
  Before, such an address was refused ("must not contain … a fragment"), or the API call was redirected.
- **Redirect errors explain themselves:** a refused redirect now says where the server pointed. When it is a
  sign-in page, the error says the API key was not accepted (enabled? expired? copied completely?). When it is a
  different host, it says so.
