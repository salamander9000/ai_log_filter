#!/usr/bin/env bash
#
# Setup OpenSearch Dashboards: index patterns, visualizations, and dashboard.
#
# Layout (every panel clearly labeled by layer):
#   Row 1: Layer 3 summary metrics
#   Row 2: Layer 3 confirmed threats detail table
#   Row 3: Layer 3 all results table (confirmed + false positive + failed)
#   Row 4: Layer 2 summary + Layer 2/3 pending queues
#   Row 5: Layer 2 LLM analysis detail table
#   Row 6: Layer 1 events overview
#   Row 7: Layer 1 system stats
#
# Usage: ./setup-dashboards.sh [DASHBOARDS_URL]
#

set -euo pipefail

DASHBOARDS_URL="${1:-http://localhost:5601}"
API="${DASHBOARDS_URL}/api/saved_objects"
OSD_HEADER='osd-xsrf: true'

echo "=== Setting up OpenSearch Dashboards at ${DASHBOARDS_URL} ==="

echo "Waiting for Dashboards to be ready..."
for i in $(seq 1 60); do
    if curl -s "${DASHBOARDS_URL}/api/status" | grep -q '"state":"green"\|"state":"yellow"'; then
        echo "Dashboards ready."
        break
    fi
    echo "  attempt $i/60 ..."
    sleep 5
done

create_object() {
    local type="$1" id="$2" bodyfile="$3"
    curl -s -X DELETE "${API}/${type}/${id}" -H "${OSD_HEADER}" > /dev/null 2>&1 || true
    local result
    result=$(curl -s -w "\n%{http_code}" -X POST "${API}/${type}/${id}?overwrite=true" \
        -H "Content-Type: application/json" -H "${OSD_HEADER}" \
        -d @"${bodyfile}" 2>&1)
    local http_code
    http_code=$(echo "$result" | tail -1)
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        echo "  -> OK"
    else
        echo "  -> FAILED (${http_code})"
        echo "$result" | head -3
    fi
}

TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

# ===== INDEX PATTERNS =====
echo ""
echo "--- Index Patterns ---"
for IDX in logs-processed logs-anomalies logs-stats logs-threats; do
    echo "  ${IDX}"
    cat > "${TMPDIR}/b.json" <<ENDJSON
{"attributes":{"title":"${IDX}","timeFieldName":"@timestamp"}}
ENDJSON
    create_object "index-pattern" "${IDX}" "${TMPDIR}/b.json"
done
curl -s -X POST "${DASHBOARDS_URL}/api/opensearch-dashboards/settings" \
    -H "Content-Type: application/json" -H "${OSD_HEADER}" \
    -d '{"changes":{"defaultIndex":"logs-processed"}}' > /dev/null 2>&1

# ===== LAYER 3 VISUALIZATIONS =====
echo ""
echo "--- Layer 3 Visualizations ---"

echo "  Layer 3: Total Analyzed"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 3: Total Analyzed","visState":"{\"title\":\"Layer 3: Total Analyzed\",\"type\":\"metric\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"}],\"params\":{\"addTooltip\":true,\"addLegend\":false,\"type\":\"metric\",\"metric\":{\"percentageMode\":false,\"useRanges\":false,\"colorSchema\":\"Green to Red\",\"metricColorMode\":\"None\",\"colorsRange\":[{\"from\":0,\"to\":10000}],\"labels\":{\"show\":true},\"invertColors\":false,\"style\":{\"bgFill\":\"#000\",\"bgColor\":false,\"labelColor\":false,\"subText\":\"events correlated\",\"fontSize\":48}}}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-threats\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l3-total" "${TMPDIR}/b.json"

echo "  Layer 3: Confirmed Threats"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 3: Confirmed Threats","visState":"{\"title\":\"Layer 3: Confirmed Threats\",\"type\":\"metric\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"}],\"params\":{\"addTooltip\":true,\"addLegend\":false,\"type\":\"metric\",\"metric\":{\"percentageMode\":false,\"useRanges\":false,\"colorSchema\":\"Green to Red\",\"metricColorMode\":\"None\",\"colorsRange\":[{\"from\":0,\"to\":10000}],\"labels\":{\"show\":true},\"invertColors\":false,\"style\":{\"bgFill\":\"#000\",\"bgColor\":false,\"labelColor\":false,\"subText\":\"confirmed threats\",\"fontSize\":48}}}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-threats\",\"query\":{\"query\":\"confirmed:true\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l3-confirmed" "${TMPDIR}/b.json"

echo "  Layer 3: Confirmed vs False Positive"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 3: Confirmed vs False Positive","visState":"{\"title\":\"Layer 3: Confirmed vs False Positive\",\"type\":\"horizontal_bar\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"confirmed\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":2},\"schema\":\"segment\"}],\"params\":{\"type\":\"horizontal_bar\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"BottomAxis-1\",\"type\":\"value\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"normal\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\"}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-threats\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l3-confirmed-vs-fp" "${TMPDIR}/b.json"

echo "  Layer 3: Attack Types"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 3: Attack Types","visState":"{\"title\":\"Layer 3: Attack Types\",\"type\":\"pie\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"attack_type\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10},\"schema\":\"segment\"}],\"params\":{\"type\":\"pie\",\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true,\"labels\":{\"show\":true,\"values\":true,\"last_level\":true,\"truncate\":100}}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-threats\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l3-attack-types" "${TMPDIR}/b.json"

echo "  Layer 3: Pending Queue"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 3: Pending Queue","visState":"{\"title\":\"Layer 3: Pending Queue\",\"type\":\"metric\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"}],\"params\":{\"addTooltip\":true,\"addLegend\":false,\"type\":\"metric\",\"metric\":{\"percentageMode\":false,\"useRanges\":false,\"colorSchema\":\"Green to Red\",\"metricColorMode\":\"None\",\"colorsRange\":[{\"from\":0,\"to\":10000}],\"labels\":{\"show\":true},\"invertColors\":false,\"style\":{\"bgFill\":\"#000\",\"bgColor\":false,\"labelColor\":false,\"subText\":\"awaiting L3 correlation\",\"fontSize\":48}}}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"(llm_severity:high OR llm_severity:critical) AND NOT l3_analyzed:true\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l3-pending" "${TMPDIR}/b.json"

echo "  Layer 3: Confirmed Threats Detail (table)"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 3: Confirmed Threats Detail","description":"Only confirmed threats","columns":["@timestamp","hostname","attack_type","severity","confidence_pct","narrative","evidence_summary","immediate_actions"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-threats\",\"query\":{\"query\":\"confirmed:true\",\"language\":\"kuery\"},\"filter\":[],\"highlightAll\":true,\"version\":true}"}}}
EOF
create_object "search" "search-l3-confirmed" "${TMPDIR}/b.json"

echo "  Layer 3: All Results (table)"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 3: All Results (confirmed + false positive)","description":"Everything L3 analyzed","columns":["@timestamp","hostname","confirmed","attack_type","severity","confidence_pct","narrative","evidence_summary","correlated_events_count"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-threats\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"highlightAll\":true,\"version\":true}"}}}
EOF
create_object "search" "search-l3-all" "${TMPDIR}/b.json"

# ===== LAYER 2 VISUALIZATIONS =====
echo ""
echo "--- Layer 2 Visualizations ---"

echo "  Layer 2: Threat Categories"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 2: Threat Categories","visState":"{\"title\":\"Layer 2: Threat Categories\",\"type\":\"pie\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"llm_threat_category\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10},\"schema\":\"segment\"}],\"params\":{\"type\":\"pie\",\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true,\"labels\":{\"show\":true,\"values\":true,\"last_level\":true,\"truncate\":100}}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"llm_analyzed:true\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l2-threat-categories" "${TMPDIR}/b.json"

echo "  Layer 2: Severity Breakdown"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 2: Severity Breakdown","visState":"{\"title\":\"Layer 2: Severity Breakdown\",\"type\":\"horizontal_bar\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"llm_severity\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":5},\"schema\":\"segment\"}],\"params\":{\"type\":\"horizontal_bar\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"BottomAxis-1\",\"type\":\"value\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"normal\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\"}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"llm_analyzed:true\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l2-severity" "${TMPDIR}/b.json"

echo "  Layer 2: Pending Analysis"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 2: Pending Analysis","visState":"{\"title\":\"Layer 2: Pending Analysis\",\"type\":\"metric\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"}],\"params\":{\"addTooltip\":true,\"addLegend\":false,\"type\":\"metric\",\"metric\":{\"percentageMode\":false,\"useRanges\":false,\"colorSchema\":\"Green to Red\",\"metricColorMode\":\"None\",\"colorsRange\":[{\"from\":0,\"to\":10000}],\"labels\":{\"show\":true},\"invertColors\":false,\"style\":{\"bgFill\":\"#000\",\"bgColor\":false,\"labelColor\":false,\"subText\":\"awaiting L2 LLM\",\"fontSize\":48}}}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"llm_analyzed:false AND NOT llm_skipped:true\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l2-pending" "${TMPDIR}/b.json"

echo "  Layer 2: Queue Depth"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 2: Queue Depth","visState":"{\"title\":\"Layer 2: Queue Depth\",\"type\":\"line\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"max\",\"params\":{\"field\":\"llm_queue_depth\"},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-1h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"interval\":\"auto\",\"min_doc_count\":1},\"schema\":\"segment\"}],\"params\":{\"type\":\"line\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Queue depth\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"area\",\"mode\":\"normal\",\"data\":{\"label\":\"Queue depth\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":false}],\"addTooltip\":true,\"addLegend\":false,\"legendPosition\":\"right\"}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-stats\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l2-queue-depth" "${TMPDIR}/b.json"

echo "  Layer 2: LLM Analysis Results (table)"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 2: LLM Analysis Results","description":"L2 analyzed events (excluding benign_anomaly)","columns":["@timestamp","hostname","process","llm_threat_category","llm_severity","llm_explanation","anomaly_score","llm_recommended_action","message"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"llm_analyzed:true AND NOT llm_threat_category:benign_anomaly\",\"language\":\"kuery\"},\"filter\":[],\"highlightAll\":true,\"version\":true}"}}}
EOF
create_object "search" "search-l2-results" "${TMPDIR}/b.json"

# ===== LAYER 1 VISUALIZATIONS =====
echo ""
echo "--- Layer 1 Visualizations ---"

echo "  Layer 1: Events Over Time"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 1: Events Over Time","visState":"{\"title\":\"Layer 1: Events Over Time\",\"type\":\"area\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-1h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"scaleMetricValues\":false,\"interval\":\"auto\",\"drop_partials\":false,\"min_doc_count\":1,\"extended_bounds\":{}},\"schema\":\"segment\"},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"is_anomaly\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":2},\"schema\":\"group\"}],\"params\":{\"type\":\"area\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"area\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-processed\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l1-events-over-time" "${TMPDIR}/b.json"

echo "  Layer 1: Anomaly Score Distribution"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 1: Anomaly Score Distribution","visState":"{\"title\":\"Layer 1: Anomaly Score Distribution\",\"type\":\"histogram\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"histogram\",\"params\":{\"field\":\"anomaly_score\",\"interval\":0.05,\"extended_bounds\":{}},\"schema\":\"segment\"}],\"params\":{\"type\":\"histogram\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\"}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-processed\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l1-score-dist" "${TMPDIR}/b.json"

echo "  Layer 1: Top Anomalous Hosts"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 1: Top Anomalous Hosts","visState":"{\"title\":\"Layer 1: Top Anomalous Hosts\",\"type\":\"table\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"hostname\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":20},\"schema\":\"bucket\"},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"process\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10},\"schema\":\"bucket\"}],\"params\":{\"perPage\":10,\"showPartialRows\":false,\"showMetricsAtAllLevels\":false,\"sort\":{\"columnIndex\":null,\"direction\":null},\"showTotal\":false,\"totalFunc\":\"sum\",\"percentageCol\":\"\"}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l1-top-hosts" "${TMPDIR}/b.json"

echo "  Layer 1: Suspicious Patterns"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 1: Suspicious Patterns","visState":"{\"title\":\"Layer 1: Suspicious Patterns\",\"type\":\"tagcloud\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"suspicious_categories\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":20},\"schema\":\"segment\"}],\"params\":{\"scale\":\"linear\",\"orientation\":\"single\",\"minFontSize\":18,\"maxFontSize\":72,\"showLabel\":true}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-processed\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l1-patterns" "${TMPDIR}/b.json"

echo "  Layer 1: Processing Throughput"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 1: Processing Throughput","visState":"{\"title\":\"Layer 1: Processing Throughput\",\"type\":\"line\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"avg\",\"params\":{\"field\":\"events_per_sec\"},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-1h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"interval\":\"auto\",\"min_doc_count\":1},\"schema\":\"segment\"}],\"params\":{\"type\":\"line\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Events/sec\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"line\",\"mode\":\"normal\",\"data\":{\"label\":\"Events/sec\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":false,\"legendPosition\":\"right\"}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-stats\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l1-throughput" "${TMPDIR}/b.json"

echo "  Layer 1: Anomaly Rate"
cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"Layer 1: Anomaly Rate (%)","visState":"{\"title\":\"Layer 1: Anomaly Rate (%)\",\"type\":\"line\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"avg\",\"params\":{\"field\":\"anomaly_rate_pct\"},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-1h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"interval\":\"auto\",\"min_doc_count\":1},\"schema\":\"segment\"}],\"params\":{\"type\":\"line\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Anomaly %\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"line\",\"mode\":\"normal\",\"data\":{\"label\":\"Anomaly %\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":false,\"legendPosition\":\"right\"}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"index\":\"logs-stats\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}}}
EOF
create_object "visualization" "viz-l1-anomaly-rate" "${TMPDIR}/b.json"

# ===== DASHBOARD =====
echo ""
echo "--- Dashboard ---"

# Grid layout (48 columns):
# y=0  h=8:  L3:Total(8) | L3:Confirmed(8) | L3:ConfVsFP(16) | L3:AttackTypes(16)
# y=8  h=14: L3: Confirmed Threats Detail (48w)
# y=22 h=14: L3: All Results (48w)
# y=36 h=8:  L2:ThreatCat(10) | L2:Severity(10) | L2:Pending(10) | L3:Pending(10) | L2:Queue(8)
# y=44 h=14: L2: LLM Analysis Results (48w)
# y=58 h=12: L1:Events(20) | L1:ScoreDist(14) | L1:TopHosts(14)
# y=70 h=10: L1:Patterns(16) | L1:Throughput(16) | L1:AnomalyRate(16)

cat > "${TMPDIR}/b.json" <<'EOF'
{"attributes":{"title":"AI Log Filter - PoC Dashboard","description":"Three-layer AI log analysis: L3 correlation -> L2 LLM classification -> L1 ML scoring","panelsJSON":"[{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":0,\"w\":8,\"h\":8,\"i\":\"1\"},\"id\":\"viz-l3-total\",\"panelIndex\":\"1\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":8,\"y\":0,\"w\":8,\"h\":8,\"i\":\"2\"},\"id\":\"viz-l3-confirmed\",\"panelIndex\":\"2\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":16,\"y\":0,\"w\":16,\"h\":8,\"i\":\"3\"},\"id\":\"viz-l3-confirmed-vs-fp\",\"panelIndex\":\"3\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":32,\"y\":0,\"w\":16,\"h\":8,\"i\":\"4\"},\"id\":\"viz-l3-attack-types\",\"panelIndex\":\"4\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":8,\"w\":48,\"h\":14,\"i\":\"5\"},\"id\":\"search-l3-confirmed\",\"panelIndex\":\"5\",\"type\":\"search\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":22,\"w\":48,\"h\":14,\"i\":\"6\"},\"id\":\"search-l3-all\",\"panelIndex\":\"6\",\"type\":\"search\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":36,\"w\":10,\"h\":8,\"i\":\"7\"},\"id\":\"viz-l2-threat-categories\",\"panelIndex\":\"7\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":10,\"y\":36,\"w\":10,\"h\":8,\"i\":\"8\"},\"id\":\"viz-l2-severity\",\"panelIndex\":\"8\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":20,\"y\":36,\"w\":10,\"h\":8,\"i\":\"9\"},\"id\":\"viz-l2-pending\",\"panelIndex\":\"9\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":30,\"y\":36,\"w\":10,\"h\":8,\"i\":\"10\"},\"id\":\"viz-l3-pending\",\"panelIndex\":\"10\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":40,\"y\":36,\"w\":8,\"h\":8,\"i\":\"11\"},\"id\":\"viz-l2-queue-depth\",\"panelIndex\":\"11\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":44,\"w\":48,\"h\":14,\"i\":\"12\"},\"id\":\"search-l2-results\",\"panelIndex\":\"12\",\"type\":\"search\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":58,\"w\":20,\"h\":12,\"i\":\"13\"},\"id\":\"viz-l1-events-over-time\",\"panelIndex\":\"13\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":20,\"y\":58,\"w\":14,\"h\":12,\"i\":\"14\"},\"id\":\"viz-l1-score-dist\",\"panelIndex\":\"14\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":34,\"y\":58,\"w\":14,\"h\":12,\"i\":\"15\"},\"id\":\"viz-l1-top-hosts\",\"panelIndex\":\"15\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":70,\"w\":16,\"h\":10,\"i\":\"16\"},\"id\":\"viz-l1-patterns\",\"panelIndex\":\"16\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":16,\"y\":70,\"w\":16,\"h\":10,\"i\":\"17\"},\"id\":\"viz-l1-throughput\",\"panelIndex\":\"17\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":32,\"y\":70,\"w\":16,\"h\":10,\"i\":\"18\"},\"id\":\"viz-l1-anomaly-rate\",\"panelIndex\":\"18\",\"type\":\"visualization\",\"version\":\"2.18.0\"}]","optionsJSON":"{\"hidePanelTitles\":false,\"useMargins\":true}","timeRestore":true,"timeTo":"now","timeFrom":"now-1h","refreshInterval":{"pause":false,"value":10000},"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"id":"viz-l3-total","name":"panel_1","type":"visualization"},{"id":"viz-l3-confirmed","name":"panel_2","type":"visualization"},{"id":"viz-l3-confirmed-vs-fp","name":"panel_3","type":"visualization"},{"id":"viz-l3-attack-types","name":"panel_4","type":"visualization"},{"id":"search-l3-confirmed","name":"panel_5","type":"search"},{"id":"search-l3-all","name":"panel_6","type":"search"},{"id":"viz-l2-threat-categories","name":"panel_7","type":"visualization"},{"id":"viz-l2-severity","name":"panel_8","type":"visualization"},{"id":"viz-l2-pending","name":"panel_9","type":"visualization"},{"id":"viz-l3-pending","name":"panel_10","type":"visualization"},{"id":"viz-l2-queue-depth","name":"panel_11","type":"visualization"},{"id":"search-l2-results","name":"panel_12","type":"search"},{"id":"viz-l1-events-over-time","name":"panel_13","type":"visualization"},{"id":"viz-l1-score-dist","name":"panel_14","type":"visualization"},{"id":"viz-l1-top-hosts","name":"panel_15","type":"visualization"},{"id":"viz-l1-patterns","name":"panel_16","type":"visualization"},{"id":"viz-l1-throughput","name":"panel_17","type":"visualization"},{"id":"viz-l1-anomaly-rate","name":"panel_18","type":"visualization"}]}
EOF
create_object "dashboard" "dashboard-ai-log-filter" "${TMPDIR}/b.json"

echo ""
echo "=== Dashboard setup complete! ==="
echo ""
echo "Open: ${DASHBOARDS_URL}/app/dashboards#/view/dashboard-ai-log-filter"
echo ""
echo "Layout:"
echo "  ROW 1: Layer 3: Total | Confirmed | Confirmed vs FP | Attack Types"
echo "  ROW 2: Layer 3: Confirmed Threats Detail (confirmed only)"
echo "  ROW 3: Layer 3: All Results (confirmed + false positive + failed)"
echo "  ROW 4: Layer 2: Threat Cat | Severity | L2 Pending | L3 Pending | L2 Queue"
echo "  ROW 5: Layer 2: LLM Analysis Results"
echo "  ROW 6: Layer 1: Events Over Time | Score Distribution | Top Hosts"
echo "  ROW 7: Layer 1: Suspicious Patterns | Throughput | Anomaly Rate"
