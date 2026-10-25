#!/usr/bin/env python3
"""After the fixed-backend HTTP gate, apply small client-only usability corrections.

Does not rebuild/change the serving backend, gateway, database schema or model.
"""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

def main():
    folder=ROOT/'observability/runtime/private-backups/siem-upgrade-20261023-r1'
    gates=[json.loads(p.read_text()) for p in folder.glob('operational-gate-*.receipt.private.json')]
    assert any(v.get('status')=='SIEM_ONE_HOUR_HTTP_GATE_PASS' and v.get('continuous_seconds',0)>=3600 for v in gates),'Finish the immutable backend gate first'
    p=ROOT/'desktop-client/src/main/java/com/flarefitness/monitor/controller/DashboardController.java';s=p.read_text()
    assert 'private void refreshHeaderHealth()' not in s,'Client correction already applied'
    s=s.replace('    private boolean configuringFilters;','    private boolean configuringFilters;\n    private long headerGeneration;\n    private CompletableFuture<?> headerRequest;')
    s=s.replace('        if(defaultQueueTier()==null) showOverview();else showAlerts();','        if(defaultQueueTier()==null) showOverview();else showAlerts();\n        refreshHeaderHealth();',1)
    s=s.replace('    @FXML private void manualRefresh() {','    @FXML private void manualRefresh() {\n        refreshHeaderHealth();')
    s=s.replace('    private void refreshCurrentView() {','    private void refreshCurrentView() {\n        if(signingOut)return;\n        refreshHeaderHealth();')
    # A session-wide status probe must not depend on visiting Dashboard first.
    method='''    private void refreshHeaderHealth() {
        if(signingOut || api==null)return;
        long generation=++headerGeneration;
        if(headerRequest!=null && !headerRequest.isDone())headerRequest.cancel(true);
        headerRequest=api.status().whenComplete((status,error)->Platform.runLater(()->{
            if(signingOut || generation!=headerGeneration)return;
            if(error!=null){connectionLabel.setText("BACKEND UNAVAILABLE");connectionLabel.getStyleClass().setAll("status-pill","status-error");return;}
            boolean available=status.enabled() && status.elasticsearchAvailable();
            connectionLabel.setText(!status.enabled()?"PIPELINE DISABLED":available?"ELASTIC ONLINE":"ELASTIC OFFLINE");
            connectionLabel.getStyleClass().setAll("status-pill",available?"status-ok":"status-error");
        }));
    }

'''
    s=s.replace('    private void refreshCurrentView() {',method+'    private void refreshCurrentView() {',1)
    s=s.replace('        signingOut = true;currentView="signed-out";','        signingOut = true;currentView="signed-out";\n        ++headerGeneration;if(headerRequest!=null)headerRequest.cancel(true);',1)
    s=s.replace('        signingOut=true;currentView="signed-out";','        signingOut=true;currentView="signed-out";\n        ++headerGeneration;if(headerRequest!=null)headerRequest.cancel(true);',1)
    start=s.index('        VBox intelligence=new VBox(10);',s.index('@FXML private void showGeoIntelligence()'))
    end=s.index('        Tab locations=',start)
    s=s[:start]+'''        VBox intelligence=new VBox(10),reputationRows=new VBox(8);
        TextField ip=new TextField();ip.setPromptText("Public IP");
        Label feedback=stateLabel("Provider reputation is investigation context; private and TEST-NET IPs are excluded.","muted");
        java.util.concurrent.atomic.AtomicLong lookupGeneration=new java.util.concurrent.atomic.AtomicLong();
        ip.textProperty().addListener((o,old,value)->{lookupGeneration.incrementAndGet();reputationRows.getChildren().clear();feedback.setText("Search the public IP to load its cached reputation.");});
        Button lookup=actionButton("Lookup cached intelligence",()->{
            String requestedIp=ip.getText().trim();long generation=lookupGeneration.incrementAndGet();
            feedback.setText("Loading cached reputation for "+requestedIp+"…");
            api.ipIntelligence(requestedIp).whenComplete((items,error)->Platform.runLater(()->{
                if(signingOut || !"geo-intelligence".equals(currentView) || generation!=lookupGeneration.get() || !requestedIp.equals(ip.getText().trim()))return;
                reputationRows.getChildren().clear();
                if(error!=null){feedback.setText(message(error));return;}
                for(var item:items)reputationRows.getChildren().add(stateLabel(item.ipAddress()+" · "+item.provider()+" · "+item.status()+" · "+safe(item.dataProvenance())
                    +"\\nCountry "+safe(item.countryCode())+" · ASN "+safe(item.asn())+" · "+safe(item.asName())
                    +"\\nAbuse score "+(item.abuseScore()==null?"unavailable":item.abuseScore())+" · reports "+(item.totalReports()==null?"unavailable":item.totalReports())
                    +"\\nAnonymous "+(item.anonymousFlag()==null?"unavailable":item.anonymousFlag())+" · hosting "+(item.hostingFlag()==null?"unavailable":item.hostingFlag())
                    +"\\nObserved UTC "+safeTime(item.observedAt())+" · expires UTC "+safeTime(item.expiresAt()),"note-card"));
                feedback.setText(items.isEmpty()?"No cached public-IP intelligence for "+requestedIp:items.size()+" provider results for "+requestedIp);
            }));
        });
        Button refresh=secondaryButton("Request provider refresh",()->{
            String requestedIp=ip.getText().trim();long generation=lookupGeneration.incrementAndGet();
            api.requestIpLookup(requestedIp,"SOC_MANUAL_REVIEW").whenComplete((result,error)->Platform.runLater(()->{
                if(signingOut || !"geo-intelligence".equals(currentView) || generation!=lookupGeneration.get() || !requestedIp.equals(ip.getText().trim()))return;
                feedback.setText(error==null?"Lookup PENDING for "+requestedIp+". Load the cache again after the worker completes.":message(error));
            }));
        });
        intelligence.getChildren().addAll(new javafx.scene.layout.FlowPane(8,8,ip,lookup,refresh),feedback,reputationRows);
'''+s[end:]
    p.write_text(s)
    p=ROOT/'desktop-client/src/main/java/com/flarefitness/monitor/FlareSecurityApp.java';s=p.read_text().replace('        primaryStage.setOnCloseRequest(null);','        primaryStage.setOnCloseRequest(null);\n        primaryStage.setFullScreen(false);primaryStage.setMaximized(false);',1);p.write_text(s)
    p=ROOT/'desktop-client/src/test/java/com/flarefitness/monitor/controller/WorkspaceInteractionTest.java';s=p.read_text();needle='        @Override public CompletableFuture<SiemModels.IncidentDetail> incident(String id)';s=s.replace(needle,'        @Override public CompletableFuture<SiemModels.Status> status(){return CompletableFuture.completedFuture(new SiemModels.Status(true,true,null,null,null));}\n'+needle)
    compact_test="""    @Test void loginRestoresCompactSizeAfterMaximizedDashboard() throws Exception {
        fx(()->{
            Stage stage=new Stage();new FlareSecurityApp().start(stage);
            try{stage.setMinWidth(1000);stage.setMinHeight(680);stage.setWidth(1440);stage.setHeight(900);stage.setMaximized(true);
                FlareSecurityApp.showLogin();assertFalse(stage.isMaximized());assertEquals(480,stage.getMinWidth());assertEquals(480,stage.getMinHeight());
                assertTrue(stage.getWidth()<=650);assertTrue(stage.getHeight()<=570);assertNotNull(stage.getScene().lookup("#username"));
            }finally{stage.close();}return null;
        });
    }
"""
    s=s.replace('    @Test void loginSidebarAndNativeViewerRenderAtBothAcceptanceSizes()',compact_test+'    @Test void loginSidebarAndNativeViewerRenderAtBothAcceptanceSizes()');p.write_text(s)
    p=ROOT/'desktop-client/src/test/java/com/flarefitness/monitor/controller/LiveWorkspaceAcceptanceTest.java';s=p.read_text().replace('                ready(()->field(controller[0],"incidentTable")!=null);','                ready(()->field(controller[0],"incidentTable")!=null);\n                ready(()->"ELASTIC ONLINE".equals(((Label)field(controller[0],"connectionLabel")).getText()));');p.write_text(s)
    (folder/'ui-followup.checkpoint.private.json').write_text(json.dumps({'status':'CLIENT_SOURCE_UPDATED_PENDING_TESTS','backend_image_changed':False,'model_changed':False,'changes':['session-wide pipeline header','login restores compact window','reputation refresh and full provider context with query generation']}))
    print('CLIENT_ONLY_CORRECTIONS_APPLIED')

if __name__=='__main__':main()
