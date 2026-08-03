# See-Know Enterprise Features Guide
**Status:** Phase 2.4 (To-Be Implemented)

## Overview
This guide covers enterprise-only features in the See-Know module, including Discord history export, raw message access, and advanced reporting.

## Enterprise Plan Tier

### Features Included
- [ ] `/enterprise/discord/history` — Historical Discord conversation archive
- [ ] `/enterprise/discord/messages` — Raw message content export
- [ ] `/enterprise/discord/export` — Packaged ZIP export with metadata
- [ ] Advanced cascade resolution (up to 5 hops)
- [ ] Priority support queue
- [ ] Custom SLA (99.9% uptime)
- [ ] 5,000 daily credits (vs. 1,000 pro)

### Pricing
- Standard enterprise plan: Contact sales
- Volume discounts available for 10M+ queries/month

## Upgrade Process

### Step 1: Purchase Enterprise Plan
1. Visit https://see-know.ru/plans
2. Select "Enterprise" tier
3. Provide billing information
4. Receive new API key (seek-...)

### Step 2: Activate in HSE
```bash
# Update API key
echo 'HUNTSMAN_SEEKNOW_KEY=seek-your-enterprise-key' >> ~/.huntsman.env

# Verify tier detection
hse doctor
# Look for "SeekNow account: Enterprise ✓"
```

## Discord History Export

### Use Case
Export complete Discord conversation history for security investigation, compliance, or account recovery.

### Example: Query Discord History
```bash
hse scan --value discord-user-id-123456789
# Automatically detects enterprise tier
# Includes /enterprise/discord/history in cascade
```

### API Details
- **Endpoint:** `GET /enterprise/discord/history`
- **Cost:** 5 credits per user
- **Latency:** ~10-15 seconds
- **Response:** Conversation list with timestamps and participant info

### Response Format
```json
{
  "discord_id": "123456789",
  "history": [
    {
      "channel_id": "...",
      "channel_name": "...",
      "message_count": 1234,
      "date_range": ["2023-01-01", "2024-07-22"],
      "participants": ["user1", "user2", ...],
      "preview": "Last 3 messages..."
    }
  ]
}
```

## Raw Message Export

### Use Case
Extract raw message content for threat intelligence, anomaly detection, or credential discovery.

### API Details
- **Endpoint:** `GET /enterprise/discord/messages`
- **Cost:** 5 credits per user (+ per message payload)
- **Latency:** ~15-20 seconds
- **Response:** Message list with full content

### Example Response
```json
{
  "discord_id": "123456789",
  "messages": [
    {
      "message_id": "...",
      "channel": "...",
      "author": "...",
      "timestamp": "2024-07-20T15:30:00Z",
      "content": "API key: sk-ant-...redacted...",
      "attachments": [...]
    }
  ]
}
```

### Automatic Extraction
HSE automatically extracts from message content:
- Email addresses
- Phone numbers
- API keys (80+ patterns recognized)
- URLs and domains
- Cryptocurrency addresses

## ZIP Export Workflow

### Use Case
Download complete Discord account archive for offline analysis or compliance records.

### API Details
- **Endpoint:** `GET /enterprise/discord/export`
- **Cost:** 5 credits per user
- **Latency:** ~20-30 seconds
- **Response:** ZIP download URL

### Contents
```
discord-export-123456789.zip
├── metadata.json
│   ├── account_id
│   ├── export_date
│   ├── total_messages
│   ├── date_range
│   └── channels
├── conversations/
│   ├── channel-1/
│   │   ├── messages.csv
│   │   ├── attachments/
│   │   └── metadata.json
│   └── ...
├── entities.json (extracted API keys, emails, etc.)
└── summary.txt
```

## Budget Management for Enterprise

### Daily Credits Allocation
- Free: 300 credits/day
- Pro: 1,000 credits/day
- Enterprise: 5,000 credits/day

### Cost Breakdown
```
/search: 1 credit
/search/deep: 1 credit (if fast /search returned empty)
/username/social: 1 credit
/discord/user: 1 credit
/enterprise/discord/history: 5 credits ← enterprise only
/enterprise/discord/messages: 5 credits ← enterprise only
/enterprise/discord/export: 5 credits ← enterprise only
```

### Optimization Tips
1. Use fast `/search` first, fallback to `/search/deep` only on miss
2. Batch similar targets to maximize cache hits
3. Limit cascade depth (3 hops default, tunable)
4. Schedule bulk operations during low-traffic windows

## SLA & Support

### Enterprise SLA
- **Uptime:** 99.9% (max 43 minutes/month downtime)
- **Response Time:** p95 <10s for fast endpoints, <45s for /search/deep
- **Support:** Priority email queue, <2 hour response time

### Monitoring
Check service status:
```bash
hse scan --value "status-check"
# Returns: Service health for integrated data sources
```

### Escalation
- Outage/Critical: Email support@see-know.ru
- Response time SLA: 1 hour for P1 issues

## Troubleshooting

### "Plan tier verification failed"
- Ensure API key is up to date
- Check `hse doctor` for tier detection
- Verify outbound connectivity to see-know.ru

### "Insufficient credits"
- Current daily limit: `hse scan --dry-run` to preview cost
- Upgrade plan or wait for daily reset (UTC midnight)

### "Enterprise endpoint not available"
- Confirm enterprise tier: `hse doctor`
- Check API key: `echo $HUNTSMAN_SEEKNOW_KEY`
- Verify plan tier detection is working

## FAQ

**Q: Can I use Discord history export for GDPR compliance?**
A: Yes. Export includes all history the user has access to. Note: See-Know only has access to Discord data found in breaches/stealer logs, not live Discord API.

**Q: How often is Discord data updated?**
A: Weekly from integrated sources (snusbase, leakcheck, intelx). Live Discord API access requires Discord API integration (not currently supported).

**Q: What's the retention period?**
A: All data is retained for 24 hours in HSE's cache. API responses are never logged or stored beyond your export.

**Q: Can I export multiple Discord users?**
A: Yes. Costs scale linearly: 5 credits × number of users.

---

**Report Generated:** Phase 2.4 (To-Be Implemented)
**Branch:** claude/see-know-gap-analysis-3yydci
