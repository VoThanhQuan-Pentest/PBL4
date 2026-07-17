#!/usr/bin/env bash
set -Eeuo pipefail

# Generates an import seed for Kibana 9.4.2. Release artifacts are subsequently
# canonicalized with the official saved-objects export API (see export script).
command -v jq >/dev/null 2>&1 || { printf 'jq is required.\n' >&2; exit 1; }

emit_search() {
  local id=$1 title=$2 query=$3 columns=$4
  jq -nc --arg id "$id" --arg title "$title" --arg query "$query" --argjson columns "$columns" '
    {type:"search",id:$id,attributes:{title:$title,description:"Synthetic Flare lab data only",columns:$columns,sort:[["@timestamp","desc"]],kibanaSavedObjectMeta:{searchSourceJSON:({query:{query:$query,language:"kuery"},filter:[],indexRefName:"kibanaSavedObjectMeta.searchSourceJSON.index"}|tojson)}},references:[{name:"kibanaSavedObjectMeta.searchSourceJSON.index",type:"index-pattern",id:"flare-nginx-logs"}]}'
}

emit_vega() {
  local id=$1 title=$2 spec=$3
  jq -nc --arg id "$id" --arg title "$title" --argjson spec "$spec" '
    {type:"visualization",id:$id,attributes:{title:$title,description:"Generated for the Flare local synthetic-data lab",visState:({title:$title,type:"vega",aggs:[],params:{spec:($spec|tojson)}}|tojson),uiStateJSON:"{}",version:1,kibanaSavedObjectMeta:{searchSourceJSON:({query:{query:"",language:"kuery"},filter:[]}|tojson)}},references:[]}'
}

base_spec() {
  local index=$1 body=$2 property=$3 mark=$4 encoding=$5
  jq -nc --arg index "$index" --argjson body "$body" --arg property "$property" --argjson mark "$mark" --argjson encoding "$encoding" '
    {"$schema":"https://vega.github.io/schema/vega-lite/v5.json",autosize:{type:"fit",contains:"padding"},data:{url:{index:$index,"%context%":true,"%timefield%":"@timestamp",body:$body},format:{property:$property}},mark:$mark,encoding:$encoding,config:{axis:{labelColor:"#c7d0d9",titleColor:"#c7d0d9"},legend:{labelColor:"#c7d0d9",titleColor:"#c7d0d9"},view:{stroke:null}}}'
}

metric_spec() {
  local index=$1 query=$2
  local body mark encoding
  # Keep the dashboard time/KQL context in Kibana's Vega request. Kibana
  # rejects a URL that combines %context%=true with a top-level body.query,
  # so scoped queries live inside filter aggregations instead.
  body=$(jq -nc --argjson query "$query" '{size:0,aggs:{value:{filter:$query}}}')
  mark='{"type":"text","fontSize":42,"fontWeight":"bold","color":"#36a2ef"}'
  encoding='{"text":{"field":"doc_count","type":"quantitative","format":","},"tooltip":[{"field":"doc_count","title":"Requests","format":","}]}'
  base_spec "$index" "$body" 'aggregations.value' "$mark" "$encoding"
}

terms_spec() {
  local index=$1 field=$2 query=$3 size=${4:-10}
  local body mark encoding
  body=$(jq -nc --arg field "$field" --argjson query "$query" --argjson size "$size" '{size:0,aggs:{filtered:{filter:$query,aggs:{values:{terms:{field:$field,size:$size}}}}}}')
  mark='{"type":"bar","cornerRadiusEnd":3,"color":"#36a2ef"}'
  encoding='{"y":{"field":"key","type":"nominal","sort":"-x","title":null},"x":{"field":"doc_count","type":"quantitative","title":"Events"},"tooltip":[{"field":"key","title":"Value"},{"field":"doc_count","title":"Events","format":","}]}'
  base_spec "$index" "$body" 'aggregations.filtered.values.buckets' "$mark" "$encoding"
}

timeseries_spec() {
  local body mark encoding
  body='{"size":0,"aggs":{"values":{"date_histogram":{"field":"@timestamp","fixed_interval":"1m","min_doc_count":0,"extended_bounds":{"min":"now-60m","max":"now"}}}}}'
  mark='{"type":"line","point":true,"color":"#36a2ef"}'
  encoding='{"x":{"field":"key","type":"temporal","title":"Time"},"y":{"field":"doc_count","type":"quantitative","title":"Requests"},"tooltip":[{"field":"key_as_string","title":"Time"},{"field":"doc_count","title":"Requests"}]}'
  base_spec 'logs-nginx.access-lab' "$body" 'aggregations.values.buckets' "$mark" "$encoding"
}

percentile_spec() {
  local body mark encoding
  body='{"size":0,"aggs":{"values":{"percentiles":{"field":"event.duration","percents":[50,95],"keyed":false}}}}'
  mark='{"type":"bar","cornerRadiusEnd":3,"color":"#7a77ff"}'
  encoding='{"x":{"field":"key","type":"ordinal","title":"Percentile"},"y":{"field":"value","type":"quantitative","title":"Nanoseconds"},"tooltip":[{"field":"key","title":"Percentile"},{"field":"value","title":"Nanoseconds","format":",.0f"}]}'
  base_spec 'logs-nginx.access-lab' "$body" 'aggregations.values.values' "$mark" "$encoding"
}

geo_map_spec() {
  jq -nc '
    {"$schema":"https://vega.github.io/schema/vega/v5.json",autosize:{type:"fit",contains:"padding"},data:[{name:"sphere",values:[{type:"Sphere"}]},{name:"points",url:{index:"logs-nginx.access-lab",body:{size:500,_source:["source.geo.location","source.ip"],query:{bool:{filter:[{range:{"@timestamp":{"%timefilter%":true}}},{exists:{field:"source.geo.location"}}]}}}},format:{property:"hits.hits"},transform:[{type:"formula",as:"lon",expr:"datum._source.source.geo.location.lon"},{type:"formula",as:"lat",expr:"datum._source.source.geo.location.lat"},{type:"geopoint",projection:"projection",fields:[{expr:"datum.lon"},{expr:"datum.lat"}],as:["x","y"]}]}],projections:[{name:"projection",type:"mercator",scale:{signal:"width / 6.3"},translate:[{signal:"width / 2"},{signal:"height / 2"}]}],marks:[{type:"shape",from:{data:"sphere"},transform:[{type:"geoshape",projection:"projection"}],encode:{update:{fill:{value:"#17212b"},stroke:{value:"#52606d"}}}},{type:"symbol",from:{data:"points"},encode:{update:{x:{field:"x"},y:{field:"y"},size:{value:80},fill:{value:"#ffb454"},fillOpacity:{value:0.75},tooltip:{signal:"datum._source.source.ip"}}}}],config:{background:"#0f1720"}}'
}

emit_dashboard() {
  local id=$1 title=$2 description=$3 panel_ids_json=$4
  jq -nc --arg id "$id" --arg title "$title" --arg description "$description" --argjson ids "$panel_ids_json" '
    def panels: [$ids|to_entries[]|. as $entry|{version:"9.4.2",type:"visualization",gridData:{x:(($entry.key%3)*16),y:((($entry.key/3)|floor)*14),w:16,h:14,i:$entry.value},panelIndex:$entry.value,embeddableConfig:{},panelRefName:("panel_"+$entry.value)}];
    {type:"dashboard",id:$id,attributes:{title:$title,description:$description,panelsJSON:(panels|tojson),optionsJSON:({useMargins:true,syncColors:false,syncCursor:true,syncTooltips:false,hidePanelTitles:false}|tojson),timeRestore:true,timeFrom:"now-24h",timeTo:"now",refreshInterval:{pause:false,value:60000},kibanaSavedObjectMeta:{searchSourceJSON:({query:{query:"",language:"kuery"},filter:[]}|tojson)}},references:[$ids[]|{name:("panel_"+.),type:"visualization",id:.}]}'
}

match_all='{"match_all":{}}'
access_index='logs-nginx.access-lab'

jq -nc '{type:"index-pattern",id:"flare-nginx-logs",attributes:{title:"logs-nginx.*-lab",timeFieldName:"@timestamp",name:"Flare Lab Nginx logs"},references:[]}'
emit_search flare-overview-events 'Flare Overview — latest requests' '*' '["source.ip","http.request.method","url.path","http.response.status_code","event.duration","user_agent.original"]'
emit_search flare-geo-events 'Flare GeoIP — public sources' 'source.geo.location: *' '["source.ip","source.geo.country_iso_code","source.geo.city_name","source.as.number","source.as.organization.name"]'
emit_search flare-security-events 'Flare Security — latest signals' 'http.response.status_code >= 400 or flare.detection.type: *' '["source.ip","url.path","http.response.status_code","flare.detection.type","flare.detection.severity"]'

emit_vega flare-total-requests 'Total requests' "$(metric_spec "$access_index" "$match_all")"
emit_vega flare-requests-timeseries 'Requests over time' "$(timeseries_spec)"
emit_vega flare-status-distribution 'Status distribution' "$(terms_spec "$access_index" 'http.response.status_code' "$match_all" 10)"
emit_vega flare-latency-percentiles 'P50 / P95 latency' "$(percentile_spec)"
emit_vega flare-top-url 'Top URL paths' "$(terms_spec "$access_index" 'url.path' "$match_all" 10)"
emit_vega flare-top-method 'Top methods' "$(terms_spec "$access_index" 'http.request.method' "$match_all" 10)"
emit_vega flare-top-source-ip 'Top source IPs' "$(terms_spec "$access_index" 'source.ip' "$match_all" 10)"
emit_vega flare-top-user-agent 'Top User-Agents' "$(terms_spec "$access_index" 'user_agent.original' "$match_all" 10)"

emit_vega flare-source-geo-map 'Source geo map' "$(geo_map_spec)"
emit_vega flare-top-country 'Top countries' "$(terms_spec "$access_index" 'source.geo.country_iso_code' '{"exists":{"field":"source.geo.location"}}' 10)"
emit_vega flare-top-city 'Top cities' "$(terms_spec "$access_index" 'source.geo.city_name' '{"exists":{"field":"source.geo.location"}}' 10)"
emit_vega flare-top-asn 'Top ASNs' "$(terms_spec "$access_index" 'source.as.organization.name' '{"exists":{"field":"source.as.number"}}' 10)"

emit_vega flare-failed-logins 'Failed logins' "$(terms_spec "$access_index" 'source.ip' '{"bool":{"filter":[{"term":{"url.path":"/api/auth/login"}},{"terms":{"http.response.status_code":[401,429]}}]}}' 10)"
emit_vega flare-security-status '401 / 403 / 404 / 429 / 5xx' "$(terms_spec "$access_index" 'http.response.status_code' '{"bool":{"should":[{"terms":{"http.response.status_code":[401,403,404,429]}},{"range":{"http.response.status_code":{"gte":500}}}],"minimum_should_match":1}}' 10)"
emit_vega flare-heuristic-type 'Heuristic type' "$(terms_spec "$access_index" 'flare.detection.type' '{"exists":{"field":"flare.detection.type"}}' 10)"
emit_vega flare-heuristic-severity 'Heuristic severity' "$(terms_spec "$access_index" 'flare.detection.severity' '{"exists":{"field":"flare.detection.severity"}}' 10)"
emit_vega flare-latest-signals 'Latest heuristic signals' "$(terms_spec "$access_index" 'flare.detection.reason' '{"exists":{"field":"flare.detection.type"}}' 10)"
emit_vega flare-detection-alerts 'Latest detection alerts' "$(terms_spec '.alerts-security.alerts-flare-lab' 'kibana.alert.rule.name' "$match_all" 10)"

emit_dashboard flare-overview 'Flare Lab — Overview' 'Request volume, status, P50/P95 latency and top request dimensions.' '["flare-total-requests","flare-requests-timeseries","flare-status-distribution","flare-latency-percentiles","flare-top-url","flare-top-method","flare-top-source-ip","flare-top-user-agent"]'
emit_dashboard flare-geoip 'Flare Lab — GeoIP' 'Public source locations with country, city and ASN summaries.' '["flare-source-geo-map","flare-top-country","flare-top-city","flare-top-asn"]'
emit_dashboard flare-security 'Flare Lab — Security' 'Authentication failures, HTTP failures, heuristics and detection alerts.' '["flare-failed-logins","flare-security-status","flare-heuristic-type","flare-heuristic-severity","flare-latest-signals","flare-detection-alerts"]'
