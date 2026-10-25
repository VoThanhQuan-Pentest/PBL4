#!/usr/bin/env python3
"""Complete client-only summary, paging and async-selection behavior after exact binary gate."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

def main():
    folder=ROOT/'observability/runtime/private-backups/siem-upgrade-20261023-r1'
    gates=[json.loads(p.read_text()) for p in folder.glob('operational-gate-*.receipt.private.json')]
    assert any(v.get('compiled_class_parity') is True and v.get('continuous_seconds',0)>=3600 for v in gates)
    p=ROOT/'desktop-client/src/main/java/com/flarefitness/monitor/controller/DashboardController.java';s=p.read_text()
    assert 'private int blockPage;' not in s
    s=s.replace('    private int incidentPage;','    private int blockPage;\n    private int incidentPage;',1)
    s=s.replace('''            incidentTable.getItems().setAll(page.content());''','''            var selectedBefore=incidentTable.getSelectionModel().getSelectedItem();
            String selectedId=selectedBefore==null?null:selectedBefore.id();
            incidentTable.getItems().setAll(page.content());
            if(pendingIncidentId==null && selectedId!=null)page.content().stream().filter(item->selectedId.equals(item.id())).findFirst().ifPresent(item->incidentTable.getSelectionModel().select(item));''',1)
    s=s.replace('''        currentView="ip-blocks";pageTitle.setText("Block IP");cancelDashboardRequests();''','''        if(!"ip-blocks".equals(currentView))blockPage=0;
        currentView="ip-blocks";pageTitle.setText("Block IP");cancelDashboardRequests();''',1)
    s=s.replace('        api.blocksWithLedger().whenComplete','        api.blocksWithLedger(blockPage).whenComplete',1)
    needle='''            VBox.setVgrow(pane.getChildren().getLast(),Priority.ALWAYS);setContent(pane);markRefreshed();'''
    replacement='''            VBox.setVgrow(pane.getChildren().getLast(),Priority.ALWAYS);
            Button previous=secondaryButton("← Previous",()->{if(blockPage>0){blockPage--;showIpBlocks();}});
            Button next=secondaryButton("Next →",()->{if(data.blocks().hasNext()){blockPage++;showIpBlocks();}});
            previous.setDisable(data.blocks().page()==0);next.setDisable(!data.blocks().hasNext());
            pane.getChildren().add(new HBox(8,previous,stateLabel("Page "+(data.blocks().page()+1)+" / "+Math.max(1,data.blocks().totalPages())+" · "+data.blocks().totalElements()+" blocks","muted"),next));
            setContent(pane);markRefreshed();'''
    assert needle in s;s=s.replace(needle,replacement,1)
    s=s.replace('''            return value.revokedAt()!=null?(applied?"RELEASED":"PENDING_RELEASE"):(applied?"APPLIED":"PENDING");''','''            if(value.revokedAt()!=null)return applied?"RELEASED":"PENDING_RELEASE";
            if(value.expiresAt()!=null&&!value.expiresAt().isAfter(LocalDateTime.now(ZoneOffset.UTC)))return "EXPIRED";
            return applied?"APPLIED":"PENDING";''',1)
    s=s.replace('''                var bounds=javafx.stage.Screen.getScreensForRectangle(contentHost.getScene().getWindow().getX(),contentHost.getScene().getWindow().getY(),1,1).getFirst().getVisualBounds();''','''                var screens=javafx.stage.Screen.getScreensForRectangle(contentHost.getScene().getWindow().getX(),contentHost.getScene().getWindow().getY(),1,1);
                var bounds=(screens.isEmpty()?javafx.stage.Screen.getPrimary():screens.getFirst()).getVisualBounds();''',1)
    s=s.replace('''            Set<String> destinations=new java.util.LinkedHashSet<>(),actors=new java.util.LinkedHashSet<>(),sources=new java.util.LinkedHashSet<>();''','''            Set<String> destinations=new java.util.LinkedHashSet<>(),actors=new java.util.LinkedHashSet<>(),sources=new java.util.LinkedHashSet<>();
            Set<String> targets=new java.util.LinkedHashSet<>(),sessions=new java.util.LinkedHashSet<>(),signals=new java.util.LinkedHashSet<>();''',1)
    needle='''                if(!"Chưa có trong log".equals(actorName)||!"Chưa có trong log".equals(actorId))actors.add(actorName+" ["+actorId+"]");'''
    extra='''
                String target=EvidenceBrowserPane.value(log,"target.user.id");if(!"Chưa có trong log".equals(target))targets.add(target);
                String session=EvidenceBrowserPane.value(log,"flare.session.pseudonym");if("Chưa có trong log".equals(session))session=EvidenceBrowserPane.value(log,"session.id");if(!"Chưa có trong log".equals(session))sessions.add(session);
                for(String key:List.of("event.action","http.response.status_code","error.message","event.reason","message")){
                    String value=EvidenceBrowserPane.value(log,key);if(!"Chưa có trong log".equals(value))signals.add(key+": "+value);
                }'''
    assert needle in s;s=s.replace(needle,needle+extra,1)
    needle='''                +"\\nTài khoản liên quan (workflow): "+safe(incident.targetUserId()));'''
    replacement='''                +"\\nTài khoản bị tác động trong trang ELK ("+targets.size()+"): "+(targets.isEmpty()?"Chưa có trong log":String.join(", ",targets))
                +"\\nSession/pseudonym trong log ("+sessions.size()+"): "+(sessions.isEmpty()?"Chưa có trong log":String.join(", ",sessions))
                +"\\nTài khoản liên quan (workflow): "+safe(incident.targetUserId()));
            signal.setText("Rule "+safe(incident.ruleId())+"\\n"+safe(incident.classificationReason())+"\\nDấu hiệu trong trang ELK: "+(signals.isEmpty()?"Chưa có trong log":String.join("\\n",signals)));'''
    assert needle in s;s=s.replace(needle,replacement,1)
    s=s.replace('''        api.containment(incident.id()).whenComplete''','''        long actionGeneration=detailGeneration;
        api.containment(incident.id()).whenComplete''',1)
    s=s.replace(''' || containment.getScene()==null)return;''',''' || actionGeneration!=detailGeneration)return;''',1)
    needle='''            for(var action:items){'''
    replacement='''            List<SiemModels.ContainmentAction> active=items.stream().filter(a->"APPLIED".equals(a.status()) && (a.expiresAt()==null || a.expiresAt().isAfter(LocalDateTime.now(ZoneOffset.UTC)))).toList();
            response.setText("Tier "+incident.queueTier()+" · Assignee "+safe(incident.assigneeUserId())+"\\nCô lập tài khoản đang hiệu lực ("+active.size()+"): "+(active.isEmpty()?"Không có":active.stream().map(a->a.targetUserId()+" · "+(a.expiresAt()==null?"Đến khi gỡ":safeTime(a.expiresAt())+" UTC")).collect(java.util.stream.Collectors.joining("; "))));
            for(var action:items){'''
    assert needle in s;s=s.replace(needle,replacement,1)
    p.write_text(s)
    p=ROOT/'desktop-client/src/main/java/com/flarefitness/monitor/api/SiemApiClient.java';s=p.read_text();needle='''    public CompletableFuture<SiemModels.BlockWorkspace> blocksWithLedger() {return get("/api/siem/prevention/blocks?size=100",SiemModels.BlockWorkspace.class);}''';replacement='''    public CompletableFuture<SiemModels.BlockWorkspace> blocksWithLedger() {return blocksWithLedger(0);}
    public CompletableFuture<SiemModels.BlockWorkspace> blocksWithLedger(int page) {return get("/api/siem/prevention/blocks?page="+page+"&size=50",SiemModels.BlockWorkspace.class);}''';assert needle in s;s=s.replace(needle,replacement,1);p.write_text(s)
    print('FINAL_CLIENT_DETAIL_PAGING_AND_GENERATION_FIXES_APPLIED')

if __name__=='__main__':main()
