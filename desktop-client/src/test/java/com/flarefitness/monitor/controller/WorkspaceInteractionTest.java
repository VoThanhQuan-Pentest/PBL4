package com.flarefitness.monitor.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import com.flarefitness.monitor.FlareSecurityApp;
import com.flarefitness.monitor.api.SiemApiClient;
import com.flarefitness.monitor.model.SiemModels;
import com.flarefitness.monitor.ui.EvidenceBrowserPane;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.lang.reflect.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.input.*;
import javafx.scene.layout.VBox;
import javafx.stage.*;
import org.junit.jupiter.api.*;

class WorkspaceInteractionTest {
    @BeforeAll static void toolkit() {
        assumeTrue(System.getenv("DISPLAY")!=null,"Run with xvfb-run.");
        try{Platform.startup(()->Platform.setImplicitExit(false));}catch(IllegalStateException e){Platform.setImplicitExit(false);}
    }
    static <T> T fx(Callable<T> action)throws Exception {FutureTask<T> task=new FutureTask<>(action);Platform.runLater(task);return task.get(15,TimeUnit.SECONDS);}
    static Object field(Object target,String name)throws Exception {Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(target);}
    static void open(DashboardController target,String id)throws Exception {Method m=target.getClass().getDeclaredMethod("openIncident",String.class);m.setAccessible(true);m.invoke(target,id);}
    static SiemModels.Incident incident(String id){var at=LocalDateTime.of(2026,10,23,12,0);return new SiemModels.Incident(id,"Case "+id,"flare","rule","192.0.2.25",at,"HIGH",90,"HIGH","INVESTIGATE","Demo workflow fixture; no live detection",false,"NEW","UNREVIEWED",null,false,0,0,at,at,at,0,"L1","ELASTIC",null);}
    static class Api extends SiemApiClient {
        final Map<String,CompletableFuture<SiemModels.IncidentDetail>> details=new HashMap<>();
        Api(){super("http://127.0.0.1:8089");details.put("a",new CompletableFuture<>());details.put("b",new CompletableFuture<>());}
        @Override public CompletableFuture<SiemModels.Page<SiemModels.Incident>> incidents(SiemModels.IncidentQuery q){return CompletableFuture.completedFuture(new SiemModels.Page<>(List.of(WorkspaceInteractionTest.incident("a"),WorkspaceInteractionTest.incident("b")),0,50,2,1,false));}
        @Override public CompletableFuture<SiemModels.Status> status(){return CompletableFuture.completedFuture(new SiemModels.Status(true,true,null,null,null));}
        @Override public CompletableFuture<SiemModels.IncidentDetail> incident(String id){return details.get(id);}
        @Override public CompletableFuture<List<SiemModels.History>> incidentHistory(String id){return CompletableFuture.completedFuture(List.of());}
        @Override public CompletableFuture<List<SiemModels.IpIntelligence>> incidentIpIntelligence(String id){return CompletableFuture.completedFuture(List.of());}
        @Override public CompletableFuture<SiemModels.Page<SiemModels.InvestigationQueueEntry>> queueSummaries(List<String> ids){return CompletableFuture.completedFuture(new SiemModels.Page<>(List.of(),0,50,0,0,false));}
        @Override public CompletableFuture<SiemModels.InvestigationSummary> investigationSummary(String id){return CompletableFuture.completedFuture(new SiemModels.InvestigationSummary(WorkspaceInteractionTest.incident(id),Map.of(),Map.of(),"NO_DETECTION_LOG",LocalDateTime.now().minusHours(1),LocalDateTime.now(),List.of()));}
        @Override public CompletableFuture<SiemModels.TimelinePage> incidentTimeline(String id,String types,boolean related,String cursor){return CompletableFuture.completedFuture(new SiemModels.TimelinePage(List.of(),null,"NO_DETECTION_LOG",LocalDateTime.now()));}
        @Override public CompletableFuture<SiemModels.EvidencePage> incidentEvidence(String id,String cursor){return CompletableFuture.completedFuture(new SiemModels.EvidencePage(List.of(),null,"NO_DETECTION_LOG"));}
        @Override public CompletableFuture<List<SiemModels.ContainmentAction>> containment(String id){return CompletableFuture.completedFuture(List.of());}
        @Override public CompletableFuture<SiemModels.Note> addNote(String id,String note){return CompletableFuture.failedFuture(new IllegalStateException("Save rejected for test"));}
    }
    static void snapshot(Parent root,String name)throws Exception {
        String folder=System.getProperty("flare.siem.visualOutput");if(folder==null)return;
        root.applyCss();root.layout();var image=root.snapshot(null,null);
        java.awt.image.BufferedImage output=new java.awt.image.BufferedImage((int)image.getWidth(),(int)image.getHeight(),java.awt.image.BufferedImage.TYPE_INT_ARGB);
        for(int y=0;y<output.getHeight();y++)for(int x=0;x<output.getWidth();x++)output.setRGB(x,y,image.getPixelReader().getArgb(x,y));
        java.nio.file.Files.createDirectories(java.nio.file.Path.of(folder));javax.imageio.ImageIO.write(output,"png",java.nio.file.Path.of(folder,name+".png").toFile());
    }
    static void chooseDialog(String text){
        for(Window w:List.copyOf(Window.getWindows()))if(w.isShowing() && w.getScene()!=null)
            for(Node n:w.getScene().getRoot().lookupAll(".button"))if(n instanceof Button b && text.equals(b.getText())){b.fire();return;}
        throw new AssertionError("Dialog button missing: "+text);
    }
    @Test void oneReusableWindowRejectsStaleResultsAndHonorsUnsavedNotes() throws Exception {
        Api api=new Api();DashboardController[] controller=new DashboardController[1];Stage[] primary=new Stage[1];
        fx(()->{FXMLLoader loader=new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));Parent root=loader.load();controller[0]=loader.getController();
            primary[0]=new Stage();Scene scene=new Scene(root,1366,768);scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());primary[0].setScene(scene);primary[0].show();
            controller[0].initializeSession(api,new SiemModels.User("l1","l1","SOC L1","Practice L1",null,null));return null;});
        try {
            fx(()->{snapshot(primary[0].getScene().getRoot(),"queue-1366x768");return null;}); // drain the incident page completion
            fx(()->{var table=(TableView<?>)field(controller[0],"incidentTable");table.getSelectionModel().select(0);assertNull(field(controller[0],"incidentStage"));
                table.fireEvent(new KeyEvent(KeyEvent.KEY_PRESSED,"","",KeyCode.ENTER,false,false,false,false));return null;});
            Stage incidentStage=fx(()->(Stage)field(controller[0],"incidentStage"));assertNotSame(primary[0],incidentStage);
            fx(()->{open(controller[0],"b");assertSame(incidentStage,field(controller[0],"incidentStage"));return null;});
            api.details.get("b").complete(new SiemModels.IncidentDetail(incident("b"),List.of()));fx(()->null);
            api.details.get("a").complete(new SiemModels.IncidentDetail(incident("a"),List.of()));fx(()->{snapshot(incidentStage.getScene().getRoot(),"incident-1100x760");return null;});
            fx(()->{assertEquals("b",field(controller[0],"openIncidentId"));assertTrue(incidentStage.getTitle().endsWith("b"));assertTrue(incidentStage.getScene().getRoot().lookupAll(".detail-meta").stream().filter(Label.class::isInstance).map(Label.class::cast).anyMatch(label->label.getText().contains("192.0.2.25")&&label.getText().toLowerCase(java.util.Locale.ROOT).contains("workflow")),"No ELK evidence must preserve the workflow source IP");
                ((TextArea)field(controller[0],"draftNote")).setText("Unsaved investigation note");Platform.runLater(()->chooseDialog("Hủy"));open(controller[0],"a");assertEquals("b",field(controller[0],"openIncidentId"));return null;});
            fx(()->{Platform.runLater(()->chooseDialog("Lưu"));open(controller[0],"a");return null;});fx(()->null);
            fx(()->{assertEquals("b",field(controller[0],"openIncidentId"));assertEquals("Unsaved investigation note",((TextArea)field(controller[0],"draftNote")).getText());
                assertTrue(((Label)field(controller[0],"draftError")).getText().contains("Save rejected"));
                Platform.runLater(()->chooseDialog("Bỏ thay đổi"));open(controller[0],"a");return null;});fx(()->null);
            fx(()->{assertEquals("a",field(controller[0],"openIncidentId"));assertSame(incidentStage,field(controller[0],"incidentStage"));controller[0].dispose();assertFalse(incidentStage.isShowing());assertNull(incidentStage.getScene());return null;});
        } finally {fx(()->{controller[0].dispose();primary[0].close();return null;});}
    }
    @Test void queueRefreshKeepsTheSelectedIncidentWhileDetailWindowIsSeparate()throws Exception{
        Api api=new Api();DashboardController[] controller=new DashboardController[1];Stage[] stage=new Stage[1];
        fx(()->{FXMLLoader loader=new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));Parent root=loader.load();controller[0]=loader.getController();stage[0]=new Stage();stage[0].setScene(new Scene(root,1366,768));stage[0].show();controller[0].initializeSession(api,new SiemModels.User("l1","l1","SOC L1","Practice L1",null,null));return null;});
        try{
            fx(()->null);
            fx(()->{var table=(TableView<?>)field(controller[0],"incidentTable");table.getSelectionModel().select(1);Method refresh=DashboardController.class.getDeclaredMethod("refreshIncidents");refresh.setAccessible(true);refresh.invoke(controller[0]);return null;});
            fx(()->{var table=(TableView<?>)field(controller[0],"incidentTable");assertNotNull(table.getSelectionModel().getSelectedItem());assertEquals("b",((SiemModels.Incident)table.getSelectionModel().getSelectedItem()).id());return null;});
        }finally{fx(()->{controller[0].dispose();stage[0].close();return null;});}
    }
    @Test void loginRestoresCompactSizeAfterMaximizedDashboard() throws Exception {
        Stage[] current=new Stage[1];
        fx(()->{current[0]=new Stage();new FlareSecurityApp().start(current[0]);return null;});
        try{
            fx(()->{FlareSecurityApp.showDashboard(new Api(),new SiemModels.User("l1","l1","SOC L1","Practice L1",null,null));current[0].setMaximized(true);return null;});
            fx(()->{FlareSecurityApp.showLogin();return null;});
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
            while(!fx(()->!current[0].isMaximized()&&current[0].getWidth()<=650&&current[0].getHeight()<=570)&&System.nanoTime()<deadline)Thread.sleep(25);
            fx(()->{assertFalse(current[0].isMaximized());assertEquals(480,current[0].getMinWidth());assertEquals(480,current[0].getMinHeight());
                assertTrue(current[0].getWidth()<=650);assertTrue(current[0].getHeight()<=570);assertNotNull(current[0].getScene().lookup("#username"));return null;});
        }finally{fx(()->{current[0].close();return null;});}
    }
    @Test void loginSidebarAndNativeViewerRenderAtBothAcceptanceSizes() throws Exception {
        fx(()->{
            FXMLLoader login=new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/login.fxml"));Parent root=login.load();
            assertNull(root.lookup("#serverUrl"));assertEquals(1,root.lookupAll(".password-field").size());
            FXMLLoader workspace=new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));Parent dashboard=workspace.load();
            Stage stage=new Stage();stage.setScene(new Scene(dashboard,1366,768));stage.getScene().getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());stage.show();dashboard.applyCss();dashboard.layout();
            Set<String> labels=new LinkedHashSet<>();dashboard.lookupAll(".nav-button").forEach(n->labels.add(((Button)n).getText()));
            assertEquals(Set.of("Dashboard","Incident queue","Block IP","History","GeoIP & IP intelligence"),labels);
            var hit=new ObjectMapper().readTree("{\"_index\":\"logs-flare.security-lab\",\"_id\":\"demo\",\"_source\":{\"unicode\":\"Tiếng Việt\",\"nested\":[true,null,3]}}");
            for(int[] size:new int[][]{{1366,768},{1920,1080}}){
                VBox viewer=new VBox(10,new CheckBox("Selected column"),EvidenceBrowserPane.json(hit));((CheckBox)viewer.getChildren().getFirst()).setSelected(true);
                Scene scene=new Scene(viewer,size[0],size[1]);scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());stage.setScene(scene);stage.setWidth(size[0]);stage.setHeight(size[1]);viewer.applyCss();viewer.layout();
                assertFalse(viewer.lookupAll(".button").isEmpty());
                String folder=System.getProperty("flare.siem.visualOutput");
                if(folder!=null){var image=viewer.snapshot(null,null);java.awt.image.BufferedImage output=new java.awt.image.BufferedImage((int)image.getWidth(),(int)image.getHeight(),java.awt.image.BufferedImage.TYPE_INT_ARGB);
                    for(int y=0;y<output.getHeight();y++)for(int x=0;x<output.getWidth();x++)output.setRGB(x,y,image.getPixelReader().getArgb(x,y));
                    java.nio.file.Files.createDirectories(java.nio.file.Path.of(folder));javax.imageio.ImageIO.write(output,"png",java.nio.file.Path.of(folder,"viewer-"+size[0]+"x"+size[1]+".png").toFile());}
            }
            stage.close();return null;
        });
    }
}
