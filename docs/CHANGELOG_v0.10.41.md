# NodeWatch v0.10.41 — "NodeWatch has stopped" false alarm, wall display stays where you are

## "NodeWatch has stopped" while NodeWatch was running
Your diagnostics show the same NodeWatch process running from its start the evening before until the export the next morning, with Mist reads every minute all night: NodeWatch had not stopped. The notice came from the page's "is NodeWatch still running?" check, which gave up too easily:
- the check waited behind slow page requests in the server's worker pool, and any slow or busy answer counted as "stopped";
- it used a kind of request (keepalive) that the browser allows only a few of at a time, so after a few slow answers the next checks failed without even reaching NodeWatch;
- it gave up after 5.5 seconds.

Now:
- the check is answered straight away, never queued behind other requests;
- an answer of any kind, even a slow or busy one, means NodeWatch is running;
- the notice only appears when NodeWatch cannot be reached at all for about 40 seconds;
- while it is shown it keeps checking, and it removes itself as soon as NodeWatch answers;
- the server accepts more simultaneous connections before refusing new ones (400, was 100).

When the page loses contact and gets it back, it now writes what happened to the application log (how long, and what each attempt got).

## Security Operations wall display
Opening a case, a country, a detection or any other page on the wall display no longer jumps back to the Watch floor at the next rotation. The wall rotates its three renditions only while nobody is using it: any click, key press or scroll pauses it, and it resumes by itself after 3 minutes without one, only from one of the three renditions. The toolbar shows "Rotating every 45 s" or "Rotation paused while in use". Data refreshes keep you on the page you are on.

## Diagnostics
- The application log was written in the Windows code page, so the diagnostics export skipped it as "binary" (it did in this export). It is now written in UTF-8 and rotated at 10 MB (three files kept); existing logs in the old encoding, and PowerShell's UTF-16 logs, are included as well, and a log over 10 MB contributes its last 5 MB.
- The export lists page requests in progress, and the application log warns when 60 or more are in progress at once (and which), so a pile-up is visible next time.
