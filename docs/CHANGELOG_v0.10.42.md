# NodeWatch v0.10.42 — the wall display stays where you put it

- **No more rotation.** Security Operations' wall display no longer cycles through Watch floor, Atlas and Case desk. It stays on whatever it shows — a rendition, a tab (Detections, Vulnerabilities, Coverage, Posture), a case or a detail page — and only the data refreshes, in place, every 30 seconds.
- **Refreshes keep the scroll position** of the page and of every scrolling panel on it.
- **The tabs, the time window and the site picker stay available on the wall**, so the screen can be set to the view you want (they were hidden in wall mode). Choosing a site or window no longer stops the automatic refresh.
- **The wall survives restarts.** Wall mode and the page it shows are remembered, so after NodeWatch restarts (or the window reloads) the screen comes back the same way. Leaving the browser's full screen no longer ends wall mode; "Exit wall display" does.
