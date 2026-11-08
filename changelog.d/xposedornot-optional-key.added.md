- The keyless XposedOrNot breach lookup now accepts an optional API key (HUNTSMAN_XPOSEDORNOT_KEY).
  When set it is sent in the `x-api-key` header to raise the per-minute rate limit, so bulk email
  scans hit fewer rate-limit refusals; the leg stays keyless by default and the breach-analytics
  answer is unchanged with or without it. The key appears on the Settings page and in the provider
  credential manifest, and is validated like every other known variable.
