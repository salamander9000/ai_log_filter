#!/usr/bin/env bash
#
# Setup OpenSearch Dashboards: index patterns, visualizations, and dashboard.
# Run this after the stack is up and some data has been indexed.
#
# Usage: ./setup-dashboards.sh [DASHBOARDS_URL]
#   Default: http://localhost:5601
#

set -euo pipefail

DASHBOARDS_URL="${1:-http://localhost:5601}"
API="${DASHBOARDS_URL}/api/saved_objects"
HEADER='Content-Type: application/json'
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

# -----------------------------------------------------------------------
# 1. Index Patterns
# -----------------------------------------------------------------------
echo ""
echo "--- Creating index patterns ---"

for IDX in logs-processed logs-anomalies logs-stats; do
    echo "Creating index pattern: ${IDX}"
    curl -s -X POST "${API}/index-pattern/${IDX}" \
        -H "${HEADER}" -H "${OSD_HEADER}" \
        -d "{
            \"attributes\": {
                \"title\": \"${IDX}\",
                \"timeFieldName\": \"@timestamp\"
            }
        }" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  -> {d.get(\"id\", \"error\")}')" 2>/dev/null || echo "  -> (may already exist)"
done

# Set default index pattern
curl -s -X POST "${DASHBOARDS_URL}/api/opensearch-dashboards/settings" \
    -H "${HEADER}" -H "${OSD_HEADER}" \
    -d '{"changes": {"defaultIndex": "logs-processed"}}' > /dev/null 2>&1

# -----------------------------------------------------------------------
# 2. Visualizations
# -----------------------------------------------------------------------
echo ""
echo "--- Creating visualizations ---"

# Viz 1: Events over time (area chart)
echo "Creating: Events Over Time"
curl -s -X POST "${API}/visualization/viz-events-over-time" \
    -H "${HEADER}" -H "${OSD_HEADER}" \
    -d '{
    "attributes": {
        "title": "Events Over Time",
        "visState": "{\"title\":\"Events Over Time\",\"type\":\"area\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-1h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"scaleMetricValues\":false,\"interval\":\"auto\",\"drop_partials\":false,\"min_doc_count\":1,\"extended_bounds\":{}},\"schema\":\"segment\"},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"is_anomaly\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":2},\"schema\":\"group\"}],\"params\":{\"type\":\"area\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"area\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false,\"thresholdLine\":{\"show\":false,\"value\":10,\"width\":1,\"style\":\"full\",\"color\":\"#E7664C\"}}}",
        "uiStateJSON": "{}",
        "description": "All processed events over time, split by anomaly status",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-processed\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}' > /dev/null 2>&1
echo "  -> done"

# Viz 2: Anomaly Score Distribution (histogram)
echo "Creating: Anomaly Score Distribution"
curl -s -X POST "${API}/visualization/viz-anomaly-score-dist" \
    -H "${HEADER}" -H "${OSD_HEADER}" \
    -d '{
    "attributes": {
        "title": "Anomaly Score Distribution",
        "visState": "{\"title\":\"Anomaly Score Distribution\",\"type\":\"histogram\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"histogram\",\"params\":{\"field\":\"anomaly_score\",\"interval\":0.05,\"extended_bounds\":{}},\"schema\":\"segment\"}],\"params\":{\"type\":\"histogram\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\"}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"}}",
        "uiStateJSON": "{}",
        "description": "Distribution of anomaly scores from the Isolation Forest model",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-processed\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}' > /dev/null 2>&1
echo "  -> done"

# Viz 3: Anomalies by Threat Category (pie chart)
echo "Creating: Threat Categories"
curl -s -X POST "${API}/visualization/viz-threat-categories" \
    -H "${HEADER}" -H "${OSD_HEADER}" \
    -d '{
    "attributes": {
        "title": "Threat Categories (LLM)",
        "visState": "{\"title\":\"Threat Categories (LLM)\",\"type\":\"pie\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"llm_threat_category\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10},\"schema\":\"segment\"}],\"params\":{\"type\":\"pie\",\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true,\"labels\":{\"show\":true,\"values\":true,\"last_level\":true,\"truncate\":100}}}",
        "uiStateJSON": "{}",
        "description": "LLM-classified threat categories for anomalous events",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}' > /dev/null 2>&1
echo "  -> done"

# Viz 4: LLM Severity Breakdown (horizontal bar)
echo "Creating: LLM Severity Breakdown"
curl -s -X POST "${API}/visualization/viz-llm-severity" \
    -H "${HEADER}" -H "${OSD_HEADER}" \
    -d '{
    "attributes": {
        "title": "LLM Severity Breakdown",
        "visState": "{\"title\":\"LLM Severity Breakdown\",\"type\":\"horizontal_bar\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"llm_severity\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":5},\"schema\":\"segment\"}],\"params\":{\"type\":\"horizontal_bar\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"BottomAxis-1\",\"type\":\"value\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"normal\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\"}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"}}",
        "uiStateJSON": "{}",
        "description": "Severity levels assigned by the LLM",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}' > /dev/null 2>&1
echo "  -> done"

# Viz 5: Top Anomalous Hosts (data table)
echo "Creating: Top Anomalous Hosts"
curl -s -X POST "${API}/visualization/viz-top-anomalous-hosts" \
    -H "${HEADER}" -H "${OSD_HEADER}" \
    -d '{
    "attributes": {
        "title": "Top Anomalous Hosts",
        "visState": "{\"title\":\"Top Anomalous Hosts\",\"type\":\"table\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"hostname\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":20},\"schema\":\"bucket\"},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"process\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10},\"schema\":\"bucket\"}],\"params\":{\"perPage\":10,\"showPartialRows\":false,\"showMetricsAtAllLevels\":false,\"sort\":{\"columnIndex\":null,\"direction\":null},\"showTotal\":false,\"totalFunc\":\"sum\",\"percentageCol\":\"\"}}",
        "uiStateJSON": "{\"vis\":{\"params\":{\"sort\":{\"columnIndex\":null,\"direction\":null}}}}",
        "description": "Hosts and processes generating the most anomalies",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}' > /dev/null 2>&1
echo "  -> done"

# Viz 6: Suspicious Pattern Categories (tag cloud)
echo "Creating: Suspicious Patterns"
curl -s -X POST "${API}/visualization/viz-suspicious-patterns" \
    -H "${HEADER}" -H "${OSD_HEADER}" \
    -d '{
    "attributes": {
        "title": "Suspicious Pattern Categories",
        "visState": "{\"title\":\"Suspicious Pattern Categories\",\"type\":\"tagcloud\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"suspicious_categories\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":20},\"schema\":\"segment\"}],\"params\":{\"scale\":\"linear\",\"orientation\":\"single\",\"minFontSize\":18,\"maxFontSize\":72,\"showLabel\":true}}",
        "uiStateJSON": "{}",
        "description": "Tag cloud of detected suspicious pattern categories",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-processed\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}' > /dev/null 2>&1
echo "  -> done"

# Viz 7: Processing Stats (line chart)
echo "Creating: Processing Throughput"
curl -s -X POST "${API}/visualization/viz-processing-stats" \
    -H "${HEADER}" -H "${OSD_HEADER}" \
    -d '{
    "attributes": {
        "title": "Processing Throughput (events/sec)",
        "visState": "{\"title\":\"Processing Throughput (events/sec)\",\"type\":\"line\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"avg\",\"params\":{\"field\":\"events_per_sec\"},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-1h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"interval\":\"auto\",\"min_doc_count\":1},\"schema\":\"segment\"}],\"params\":{\"type\":\"line\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Events/sec\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"line\",\"mode\":\"normal\",\"data\":{\"label\":\"Avg events/sec\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"}}",
        "uiStateJSON": "{}",
        "description": "AI service processing throughput over time",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-stats\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}' > /dev/null 2>&1
echo "  -> done"

# Viz 8: Anomaly Rate over time (metric)
echo "Creating: Anomaly Rate"
curl -s -X POST "${API}/visualization/viz-anomaly-rate" \
    -H "${HEADER}" -H "${OSD_HEADER}" \
    -d '{
    "attributes": {
        "title": "Anomaly Rate (%)",
        "visState": "{\"title\":\"Anomaly Rate (%)\",\"type\":\"line\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"avg\",\"params\":{\"field\":\"anomaly_rate_pct\"},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-1h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"interval\":\"auto\",\"min_doc_count\":1},\"schema\":\"segment\"}],\"params\":{\"type\":\"line\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"labels\":{\"show\":true},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"labels\":{\"show\":true},\"title\":{\"text\":\"Anomaly %\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"line\",\"mode\":\"normal\",\"data\":{\"label\":\"Anomaly Rate %\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"}}",
        "uiStateJSON": "{}",
        "description": "Percentage of events flagged as anomalous over time",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-stats\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
    }
}' > /dev/null 2>&1
echo "  -> done"

# Viz 9: Anomaly detail table (latest anomalies with LLM analysis)
echo "Creating: Latest Anomalies (detail table)"
curl -s -X POST "${API}/search/search-latest-anomalies" \
    -H "${HEADER}" -H "${OSD_HEADER}" \
    -d '{
    "attributes": {
        "title": "Latest Anomalies with LLM Analysis",
        "description": "Detailed table of recent anomalous events with AI explanations",
        "columns": ["@timestamp", "hostname", "process", "severity", "anomaly_score", "llm_threat_category", "llm_severity", "llm_explanation", "message"],
        "sort": [["@timestamp", "desc"]],
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{\"index\":\"logs-anomalies\",\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"highlightAll\":true,\"version\":true}"
        }
    }
}' > /dev/null 2>&1
echo "  -> done"

# -----------------------------------------------------------------------
# 3. Dashboard
# -----------------------------------------------------------------------
echo ""
echo "--- Creating dashboard ---"

curl -s -X POST "${API}/dashboard/dashboard-ai-log-filter" \
    -H "${HEADER}" -H "${OSD_HEADER}" \
    -d '{
    "attributes": {
        "title": "AI Log Filter - PoC Dashboard",
        "description": "Overview of AI-powered syslog anomaly detection",
        "panelsJSON": "[{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":0,\"w\":32,\"h\":12,\"i\":\"1\"},\"id\":\"viz-events-over-time\",\"panelIndex\":\"1\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":32,\"y\":0,\"w\":16,\"h\":12,\"i\":\"2\"},\"id\":\"viz-anomaly-score-dist\",\"panelIndex\":\"2\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":12,\"w\":16,\"h\":12,\"i\":\"3\"},\"id\":\"viz-threat-categories\",\"panelIndex\":\"3\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":16,\"y\":12,\"w\":16,\"h\":12,\"i\":\"4\"},\"id\":\"viz-llm-severity\",\"panelIndex\":\"4\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":32,\"y\":12,\"w\":16,\"h\":12,\"i\":\"5\"},\"id\":\"viz-top-anomalous-hosts\",\"panelIndex\":\"5\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":24,\"w\":16,\"h\":10,\"i\":\"6\"},\"id\":\"viz-suspicious-patterns\",\"panelIndex\":\"6\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":16,\"y\":24,\"w\":16,\"h\":10,\"i\":\"7\"},\"id\":\"viz-processing-stats\",\"panelIndex\":\"7\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":32,\"y\":24,\"w\":16,\"h\":10,\"i\":\"8\"},\"id\":\"viz-anomaly-rate\",\"panelIndex\":\"8\",\"type\":\"visualization\",\"version\":\"2.18.0\"},{\"embeddableConfig\":{},\"gridData\":{\"x\":0,\"y\":34,\"w\":48,\"h\":14,\"i\":\"9\"},\"id\":\"search-latest-anomalies\",\"panelIndex\":\"9\",\"type\":\"search\",\"version\":\"2.18.0\"}]",
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
        {"id": "viz-events-over-time", "name": "panel_1", "type": "visualization"},
        {"id": "viz-anomaly-score-dist", "name": "panel_2", "type": "visualization"},
        {"id": "viz-threat-categories", "name": "panel_3", "type": "visualization"},
        {"id": "viz-llm-severity", "name": "panel_4", "type": "visualization"},
        {"id": "viz-top-anomalous-hosts", "name": "panel_5", "type": "visualization"},
        {"id": "viz-suspicious-patterns", "name": "panel_6", "type": "visualization"},
        {"id": "viz-processing-stats", "name": "panel_7", "type": "visualization"},
        {"id": "viz-anomaly-rate", "name": "panel_8", "type": "visualization"},
        {"id": "search-latest-anomalies", "name": "panel_9", "type": "search"}
    ]
}' > /dev/null 2>&1
echo "  -> done"

echo ""
echo "=== Dashboard setup complete! ==="
echo ""
echo "Open your browser: ${DASHBOARDS_URL}/app/dashboards#/view/dashboard-ai-log-filter"
echo ""
echo "If visualizations show 'no data', wait a few minutes for the AI service"
echo "to process logs and index them into OpenSearch."
