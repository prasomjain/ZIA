.PHONY: demo

demo:
	@echo "Submitting 3 demo alerts to ZIA webhook..."
	@echo ""
	@echo "1) Critical KEV-listed"
	curl -sS -X POST "http://localhost:8000/api/v1/webhook/zeroday" \
	-H "Content-Type: application/json" \
	-H "x-Webhook-Secret: ${WEBHOOK_SECRET}" \
	  -d '{"tenant_id":"demo-tenant","title":"CISA KEV Critical","source":"make-demo","severity":"CRITICAL","details":{"cve":"CVE-2021-44228","src_ip":"203.0.113.45","dst_domain":"api.prod.example.com","product":"Apache Log4j","version":"2.14.1"},"actors":["APT29"]}' | tee /tmp/zia_demo_1.json
	@echo "\n"
	sleep 2
	@echo "2) Medium with high EPSS profile"
	curl -sS -X POST "http://localhost:8000/api/v1/webhook/zeroday" \
	-H "Content-Type: application/json" \
	-H "x-Webhook-Secret: ${WEBHOOK_SECRET}" \
	  -d '{"tenant_id":"demo-tenant","title":"Vendor advisory medium","source":"make-demo","severity":"MEDIUM","details":{"cve":"CVE-2023-44487","src_ip":"198.51.100.80","dst_domain":"gateway.example.com","product":"HTTP/2 stack","version":"1.3.2"}}' | tee /tmp/zia_demo_2.json
	@echo "\n"
	sleep 2
	@echo "3) Low probable FP"
	curl -sS -X POST "http://localhost:8000/api/v1/webhook/zeroday" \
	-H "Content-Type: application/json" \
	-H "x-Webhook-Secret: ${WEBHOOK_SECRET}" \
	  -d '{"tenant_id":"demo-tenant","title":"Probable false positive","source":"make-demo","severity":"LOW","details":{"cve":"CVE-2017-0144","src_ip":"192.0.2.123","dst_domain":"benign.example.org","product":"Legacy SMB","version":"patched"}}' | tee /tmp/zia_demo_3.json
	@echo "\nDone. Extract alert IDs from /tmp/zia_demo_*.json and open:"
	@echo "  http://localhost:3000/alerts/<alert_id>"
