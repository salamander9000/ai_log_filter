#!/usr/bin/env bash
#
# Setup OpenSearch Dashboards: index patterns, visualizations, and dashboard.
# Run this after the stack is up and some data has been indexed.
#
# Layout:
#   Row 1: LLM Threat Categories | LLM Severity | Pending LLM + LLM Queue
#   Row 2: LLM Analysis Detail Table (full width)
#   Row 3: Events Over Time | Anomaly Score Distribution | Top Anomalous Hosts
#   Row 4: Suspicious Patterns | Processing Throughput | Anomaly Rate
#
# Usage: ./setup-dashboards.sh [DASHBOARDS_URL]
#   Default: http://localhost:5601
#

set -euo pipefail

DASHBOARDS_URL="${1:-http://localhost:5601}"
API="${DASHBOARDS_URL}/api/saved_objects"
OSD_HEADER='osd-xsrf: true'

echo "=== Setting up OpenSearch Dashboards at ${DASHBOARDS_URL} ==="

# Wait for dashboards to be ready
echo "Waiting for Dashboards to be ready..."
for i in $(seq 1 60); do
    if curl -s "${DASHBOARDS_URL}/api/status" | grep -q '"state":"green"\|"state":"yellow"'; then
        echo "Dashboards ready."
        break
    fi
    echo "  attempt $i/60 ..."
    sleep 5
done

# Helper: create or overwrite a saved object using a temp file for the body
# This avoids all shell quoting issues
create_object() {
    local type="$1" id="$2" bodyfile="$3"
    # Delete first (ignore errors)
    curl -s -X DELETE "${API}/${type}/${id}" \
        -H "${OSD_HEADER}" > /dev/null 2>&1 || true
    # Create
    local result
    result=$(curl -s -w "\n%{http_code}" -X POST "${API}/${type}/${id}?overwrite=true" \
        -H "Content-Type: application/json" -H "${OSD_HEADER}" \
        -d @"${bodyfile}" 2>&1)
    local http_code
    http_code=$(echo "$result" | tail -1)
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        echo "  -> OK (${http_code})"
    else
        echo "  -> FAILED (${http_code})"
        echo "$result" | head -5
    fi
}

TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

# -----------------------------------------------------------------------
# 1. Index Patterns
# -----------------------------------------------------------------------
echo ""
echo "--- Creating index patterns ---"

for IDX in logs-processed logs-anomalies logs-stats; do
    echo "Creating index pattern: ${IDX}"
    cat > "${TMPDIR}/body.json" <<ENDJSON
{
    "attributes": {
        "title": "${IDX}",
        "timeFieldName": "@timestamp"
    }
}
ENDJSON
    create_object "index-pattern" "${IDX}" "${TMPDIR}/body.json"
done

# Set default index pattern
curl -s -X POST "${DASHBOARDS_URL}/api/opensearch-dashboards/settings" \
    -H "Content-Type: application/json" -H "${OSD_HEADER}" \
    -d '{"changes": {"defaultIndex": "logs-processed"}}' > /dev/null 2>&1

# -----------------------------------------------------------------------
# 2. Visualizations
# -----------------------------------------------------------------------
echo ""
echo "--- Creating visualizations ---"

# ==== ROW 1: LLM Analysis (top of dashboard) ====

# Viz: Threat Categories (donut) - LLM analyzed only
echo "Creating: Threat Categories (LLM)"
cat > "${TMPDIR}/body.json" <<'ENDJSON'
{
    "attributes": {
        "title": "Threat Categories (LLM Analyzed)",
        "visState": "{\"title\":\"Threat Categories (LLM Analyzed)\",\"type\":\"pie\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"llm_threat_category\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10},\"schema\":\"segment\"}],\"params\":{\"type\":\"pie\",\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true,\"labels\":{\"show\":true,\"values\":true,\"last_level\":true,\"truncate\":100}}}",
        "uiStateJSON": "{}",
        "description": "LLM-classified threat categories (only analyzed events)",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"llm_analyzed:true\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}
ENDJSON
create_object "visualization" "viz-threat-categories" "${TMPDIR}/body.json"

# Viz: LLM Severity Breakdown (horizontal bar) - LLM analyzed only
echo "Creating: LLM Severity Breakdown"
cat > "${TMPDIR}/body.json" <<'ENDJSON'
{
    "attributes": {
        "title": "LLM Severity Breakdown",
        "visState": "{\"title\":\"LLM Severity Breakdown\",\"type\":\"horizontal_bar\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"llm_severity\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":5},\"schema\":\"segment\"}],\"params\":{\"type\":\"horizontal_bar\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"BottomAxis-1\",\"type\":\"value\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"normal\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\"}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"}}",
        "uiStateJSON": "{}",
        "description": "Severity levels assigned by the LLM (only analyzed events)",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"llm_analyzed:true\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}
ENDJSON
create_object "visualization" "viz-llm-severity" "${TMPDIR}/body.json"

# Viz: Pending LLM Analysis (metric count)
echo "Creating: Pending LLM Analysis"
cat > "${TMPDIR}/body.json" <<'ENDJSON'
{
    "attributes": {
        "title": "Pending LLM Analysis",
        "visState": "{\"title\":\"Pending LLM Analysis\",\"type\":\"metric\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"}],\"params\":{\"addTooltip\":true,\"addLegend\":false,\"type\":\"metric\",\"metric\":{\"percentageMode\":false,\"useRanges\":false,\"colorSchema\":\"Green to Red\",\"metricColorMode\":\"None\",\"colorsRange\":[{\"from\":0,\"to\":10000}],\"labels\":{\"show\":true},\"invertColors\":false,\"style\":{\"bgFill\":\"#000\",\"bgColor\":false,\"labelColor\":false,\"subText\":\"anomalies awaiting LLM\",\"fontSize\":60}}}}",
        "uiStateJSON": "{}",
        "description": "Number of anomalies not yet analyzed by the LLM",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"llm_analyzed:false\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}
ENDJSON
create_object "visualization" "viz-pending-llm" "${TMPDIR}/body.json"

# Viz: LLM Queue Depth (line chart from stats)
echo "Creating: LLM Queue Depth"
cat > "${TMPDIR}/body.json" <<'ENDJSON'
{
    "attributes": {
        "title": "LLM Queue Depth",
        "visState": "{\"title\":\"LLM Queue Depth\",\"type\":\"line\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"max\",\"params\":{\"field\":\"llm_queue_depth\"},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-1h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"interval\":\"auto\",\"min_doc_count\":1},\"schema\":\"segment\"}],\"params\":{\"type\":\"line\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Queue depth\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"area\",\"mode\":\"normal\",\"data\":{\"label\":\"Queue depth\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":false}],\"addTooltip\":true,\"addLegend\":false,\"legendPosition\":\"right\"}}",
        "uiStateJSON": "{}",
        "description": "LLM processing queue depth over time",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-stats\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}
ENDJSON
create_object "visualization" "viz-llm-queue-depth" "${TMPDIR}/body.json"

# ==== ROW 2: LLM Detail Table ====

echo "Creating: LLM Analysis Detail Table"
cat > "${TMPDIR}/body.json" <<'ENDJSON'
{
    "attributes": {
        "title": "LLM-Analyzed Threats (Detail)",
        "description": "Anomalous events analyzed by the LLM with threat classification and explanation",
        "columns": ["@timestamp", "hostname", "process", "llm_threat_category", "llm_severity", "llm_explanation", "anomaly_score", "llm_recommended_action", "message"],
        "sort": [["@timestamp", "desc"]],
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"llm_analyzed:true\",\"language\":\"kuery\"},\"filter\":[],\"highlightAll\":true,\"version\":true}"
        }
    }
}
ENDJSON
create_object "search" "search-latest-anomalies" "${TMPDIR}/body.json"

# ==== ROW 3: Layer 1 Overview ====

# Viz: Events Over Time (area chart)
echo "Creating: Events Over Time"
cat > "${TMPDIR}/body.json" <<'ENDJSON'
{
    "attributes": {
        "title": "Events Over Time",
        "visState": "{\"title\":\"Events Over Time\",\"type\":\"area\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-1h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"scaleMetricValues\":false,\"interval\":\"auto\",\"drop_partials\":false,\"min_doc_count\":1,\"extended_bounds\":{}},\"schema\":\"segment\"},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"is_anomaly\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":2},\"schema\":\"group\"}],\"params\":{\"type\":\"area\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"area\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false,\"thresholdLine\":{\"show\":false,\"value\":10,\"width\":1,\"style\":\"full\",\"color\":\"#E7664C\"}}}",
        "uiStateJSON": "{}",
        "description": "All processed events over time, split by anomaly status",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-processed\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}
ENDJSON
create_object "visualization" "viz-events-over-time" "${TMPDIR}/body.json"

# Viz: Anomaly Score Distribution (histogram)
echo "Creating: Anomaly Score Distribution"
cat > "${TMPDIR}/body.json" <<'ENDJSON'
{
    "attributes": {
        "title": "Anomaly Score Distribution",
        "visState": "{\"title\":\"Anomaly Score Distribution\",\"type\":\"histogram\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"histogram\",\"params\":{\"field\":\"anomaly_score\",\"interval\":0.05,\"extended_bounds\":{}},\"schema\":\"segment\"}],\"params\":{\"type\":\"histogram\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\"}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"}}",
        "uiStateJSON": "{}",
        "description": "Distribution of anomaly scores from the Isolation Forest model",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-processed\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}
ENDJSON
create_object "visualization" "viz-anomaly-score-dist" "${TMPDIR}/body.json"

# Viz: Top Anomalous Hosts (data table) - using .keyword subfield
echo "Creating: Top Anomalous Hosts"
cat > "${TMPDIR}/body.json" <<'ENDJSON'
{
    "attributes": {
        "title": "Top Anomalous Hosts",
        "visState": "{\"title\":\"Top Anomalous Hosts\",\"type\":\"table\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"hostname\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":20},\"schema\":\"bucket\"},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"process\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10},\"schema\":\"bucket\"}],\"params\":{\"perPage\":10,\"showPartialRows\":false,\"showMetricsAtAllLevels\":false,\"sort\":{\"columnIndex\":null,\"direction\":null},\"showTotal\":false,\"totalFunc\":\"sum\",\"percentageCol\":\"\"}}",
        "uiStateJSON": "{\"vis\":{\"params\":{\"sort\":{\"columnIndex\":null,\"direction\":null}}}}",
        "description": "Hosts and processes generating the most anomalies",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}
ENDJSON
create_object "visualization" "viz-top-anomalous-hosts" "${TMPDIR}/body.json"

# ==== ROW 4: System Stats ====

# Viz: Suspicious Pattern Categories (tag cloud) - using keyword field
echo "Creating: Suspicious Patterns"
cat > "${TMPDIR}/body.json" <<'ENDJSON'
{
    "attributes": {
        "title": "Suspicious Pattern Categories",
        "visState": "{\"title\":\"Suspicious Pattern Categories\",\"type\":\"tagcloud\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"suspicious_categories\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":20},\"schema\":\"segment\"}],\"params\":{\"scale\":\"linear\",\"orientation\":\"single\",\"minFontSize\":18,\"maxFontSize\":72,\"showLabel\":true}}",
        "uiStateJSON": "{}",
        "description": "Tag cloud of detected suspicious pattern categories",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-processed\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}
ENDJSON
create_object "visualization" "viz-suspicious-patterns" "${TMPDIR}/body.json"

# Viz: Processing Throughput (line chart)
echo "Creating: Processing Throughput"
cat > "${TMPDIR}/body.json" <<'ENDJSON'
{
    "attributes": {
        "title": "Processing Throughput (events/sec)",
        "visState": "{\"title\":\"Processing Throughput (events/sec)\",\"type\":\"line\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"avg\",\"params\":{\"field\":\"events_per_sec\"},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-1h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"interval\":\"auto\",\"min_doc_count\":1},\"schema\":\"segment\"}],\"params\":{\"type\":\"line\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Events/sec\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"line\",\"mode\":\"normal\",\"data\":{\"label\":\"Avg events/sec\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"}}",
        "uiStateJSON": "{}",
        "description": "AI service processing throughput over time",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-stats\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}
ENDJSON
create_object "visualization" "viz-processing-stats" "${TMPDIR}/body.json"

# Viz: Anomaly Rate (line chart)
echo "Creating: Anomaly Rate"
cat > "${TMPDIR}/body.json" <<'ENDJSON'
{
    "attributes": {
        "title": "Anomaly Rate (%)",
        "visState": "{\"title\":\"Anomaly Rate (%)\",\"type\":\"line\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"avg\",\"params\":{\"field\":\"anomaly_rate_pct\"},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-1h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"interval\":\"auto\",\"min_doc_count\":1},\"schema\":\"segment\"}],\"params\":{\"type\":\"line\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Anomaly %\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"line\",\"mode\":\"normal\",\"data\":{\"label\":\"Anomaly Rate %\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"}}",
        "uiStateJSON": "{}",
        "description": "Percentage of events flagged as anomalous over time",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-stats\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}
ENDJSON
create_object "visualization" "viz-anomaly-rate" "${TMPDIR}/body.json"

# -----------------------------------------------------------------------
# 3. Dashboard
# -----------------------------------------------------------------------
echo ""
echo "--- Creating dashboard ---"

# Panel layout (48 column grid):
# Row 1 (y=0,  h=12): Threat Categories(16w) | LLM Severity(16w) | Pending(8w) + Queue(8w)
# Row 2 (y=12, h=14): LLM Detail Table (48w full width)
# Row 3 (y=26, h=12): Events Over Time(20w) | Score Distribution(14w) | Top Hosts(14w)
# Row 4 (y=38, h=10): Suspicious Patterns(16w) | Throughput(16w) | Anomaly Rate(16w)

cat > "${TMPDIR}/body.json" <<'ENDJSON'
{
    "attributes": {
        "title": "AI Log Filter - PoC Dashboard",
        "description": "AI-powered syslog anomaly detection - LLM analysis on top, Layer 1 ML below",
        "panelsJSON": "[{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":0,\"w\":16,\"h\":12,\"i\":\"1\"},\"id\":\"viz-threat-categories\",\"panelIndex\":\"1\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":16,\"y\":0,\"w\":16,\"h\":12,\"i\":\"2\"},\"id\":\"viz-llm-severity\",\"panelIndex\":\"2\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":32,\"y\":0,\"w\":8,\"h\":12,\"i\":\"3\"},\"id\":\"viz-pending-llm\",\"panelIndex\":\"3\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":40,\"y\":0,\"w\":8,\"h\":12,\"i\":\"4\"},\"id\":\"viz-llm-queue-depth\",\"panelIndex\":\"4\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":12,\"w\":48,\"h\":14,\"i\":\"5\"},\"id\":\"search-latest-anomalies\",\"panelIndex\":\"5\",\"type\":\"search\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":26,\"w\":20,\"h\":12,\"i\":\"6\"},\"id\":\"viz-events-over-time\",\"panelIndex\":\"6\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":20,\"y\":26,\"w\":14,\"h\":12,\"i\":\"7\"},\"id\":\"viz-anomaly-score-dist\",\"panelIndex\":\"7\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":34,\"y\":26,\"w\":14,\"h\":12,\"i\":\"8\"},\"id\":\"viz-top-anomalous-hosts\",\"panelIndex\":\"8\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":38,\"w\":16,\"h\":10,\"i\":\"9\"},\"id\":\"viz-suspicious-patterns\",\"panelIndex\":\"9\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":16,\"y\":38,\"w\":16,\"h\":10,\"i\":\"10\"},\"id\":\"viz-processing-stats\",\"panelIndex\":\"10\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":32,\"y\":38,\"w\":16,\"h\":10,\"i\":\"11\"},\"id\":\"viz-anomaly-rate\",\"panelIndex\":\"11\",\"type\":\"visualization\",\"version\":\"2.18.0\"}]",
        "optionsJSON": "{\"hidePanelTitles\":false,\"useMargins\":true}",
        "timeRestore": true,
        "timeTo": "now",
        "timeFrom": "now-1h",
        "refreshInterval": {
            "pause": false,
            "value": 10000
        },
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    },
    "references": [
        {"id": "viz-threat-categories", "name": "panel_1", "type": "visualization"},
        {"id": "viz-llm-severity", "name": "panel_2", "type": "visualization"},
        {"id": "viz-pending-llm", "name": "panel_3", "type": "visualization"},
        {"id": "viz-llm-queue-depth", "name": "panel_4", "type": "visualization"},
        {"id": "search-latest-anomalies", "name": "panel_5", "type": "search"},
        {"id": "viz-events-over-time", "name": "panel_6", "type": "visualization"},
        {"id": "viz-anomaly-score-dist", "name": "panel_7", "type": "visualization"},
        {"id": "viz-top-anomalous-hosts", "name": "panel_8", "type": "visualization"},
        {"id": "viz-suspicious-patterns", "name": "panel_9", "type": "visualization"},
        {"id": "viz-processing-stats", "name": "panel_10", "type": "visualization"},
        {"id": "viz-anomaly-rate", "name": "panel_11", "type": "visualization"}
    ]
}
ENDJSON
create_object "dashboard" "dashboard-ai-log-filter" "${TMPDIR}/body.json"

echo ""
echo "=== Dashboard setup complete! ==="
echo ""
echo "Open your browser: ${DASHBOARDS_URL}/app/dashboards#/view/dashboard-ai-log-filter"
echo ""
echo "Dashboard layout:"
echo "  TOP:    LLM Threat Categories | LLM Severity | Pending Count | Queue Depth"
echo "  MIDDLE: LLM Analysis Detail Table (only llm_analyzed=true)"
echo "  LOWER:  Events Over Time | Score Distribution | Top Hosts"
echo "  BOTTOM: Suspicious Patterns | Throughput | Anomaly Rate"
