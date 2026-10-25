package com.flarefitness.monitor.controller;

import static org.junit.jupiter.api.Assertions.*;
import com.flarefitness.monitor.FlareSecurityApp;
import com.flarefitness.monitor.api.SiemApiClient;
import com.flarefitness.monitor.model.SiemModels;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.input.*;
import javafx.stage.Stage;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/** Actual local API integration; uses only freshly created SOC-PRACTICE UI cases. */
@EnabledIfEnvironmentVariable(named="FLARE_SIEM_LIVE_UI",matches="true")
class LiveWorkspaceAcceptanceTest {
    @BeforeAll static void toolkit(){
        try{Platform.startup(()->Platform.setImplicitExit(false));}catch(IllegalStateException ignored){Platform.setImplicitExit(false);}
    }
    static <T> T fx(Callable<T> action)throws Exception{FutureTask<T> task=new FutureTask<>(action);Platform.runLater(task);return task.get(20,TimeUnit.SECONDS);}
    static Object field(Object target,String name)throws Exception{Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(target);}
    static void call(Object target,String name,Class<?> type,Object argument)throws Exception{Method method=target.getClass().getDeclaredMethod(name,type);method.setAccessible(true);method.invoke(target,argument);}
    static void ready(Callable<Boolean> check)throws Exception{
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(25);
        while(System.nanoTime()<deadline){if(fx(check))return;Thread.sleep(100);}fail("Live JavaFX completion timed out");
    }
    static void snapshot(Parent root,Path path)throws Exception{
        root.applyCss();root.layout();var image=root.snapshot(null,null);
        var output=new java.awt.image.BufferedImage((int)image.getWidth(),(int)image.getHeight(),java.awt.image.BufferedImage.TYPE_INT_ARGB);
        for(int y=0;y<output.getHeight();y++)for(int x=0;x<output.getWidth();x++)output.setRGB(x,y,image.getPixelReader().getArgb(x,y));
        javax.imageio.ImageIO.write(output,"png",path.toFile());
        Files.setPosixFilePermissions(path,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
    }
    @Test void liveL1AndL2UseRealNativeEvidenceInOneReusableWindow()throws Exception{
        Path output=Path.of(System.getenv("FLARE_SIEM_LIVE_UI_OUTPUT"));Files.createDirectories(output);
        String cases=System.getenv("FLARE_SIEM_PRACTICE_CASES");String[] ids=cases.split(",");assertEquals(2,ids.length);
        List<String> completed=new ArrayList<>();
        for(String tier:List.of("L1","L2")){
            SiemApiClient api=new SiemApiClient("http://127.0.0.1:8089");
            var login=api.login(System.getenv("FLARE_SOC_"+tier+"_USERNAME"),System.getenv("FLARE_SOC_"+tier+"_PASSWORD")).get(15,TimeUnit.SECONDS);
            boolean closed="CLOSED".equals(api.incident(ids[0]).get(15,TimeUnit.SECONDS).incident().status());
            DashboardController[] controller=new DashboardController[1];Stage[] primary=new Stage[1];
            try{
                fx(()->{FXMLLoader loader=new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));Parent root=loader.load();controller[0]=loader.getController();
                    primary[0]=new Stage();Scene scene=new Scene(root,1366,768);scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());primary[0].setScene(scene);primary[0].show();controller[0].initializeSession(api,login.user());return null;});
                ready(()->field(controller[0],"incidentTable")!=null);
                ready(()->"ELASTIC ONLINE".equals(((Label)field(controller[0],"connectionLabel")).getText()));
                fx(()->{Method method=DashboardController.class.getDeclaredMethod("defaultQueueTier");method.setAccessible(true);assertEquals(tier,method.invoke(controller[0]));
                    call(controller[0],"openIncident",String.class,ids[0]);return null;});
                ready(()->field(controller[0],"draftNote")!=null);
                Stage detail=fx(()->(Stage)field(controller[0],"incidentStage"));
                assertNotSame(detail,primary[0]);
                ready(()->{var pane=(javafx.scene.layout.VBox)field(controller[0],"detailTimeline");return pane.lookupAll(".table-view").stream().anyMatch(n->n instanceof TableView<?> t&&t.getItems().stream().anyMatch(item->item instanceof SiemModels.TimelineEntry entry&&"ELK".equals(entry.kind())));});
                fx(()->{Parent root=detail.getScene().getRoot();root.applyCss();root.layout();
                    assertNotNull(root.lookup(".investigation-header"));assertNotNull(root.lookup(".response-panel"));
                    TabPane incidentTabs=(TabPane)root.lookup("#incident-tabs");
                    assertEquals(List.of("Thông tin log","Dòng thời gian log"),incidentTabs.getTabs().stream().map(Tab::getText).toList());
                    if(closed)assertNotNull(root.lookup("#incident-handling-history"),"Closed incidents show their SOC processing history");
                    else assertNull(root.lookup("#incident-handling-history"),"Open incidents must not show a SOC processing timeline");
                    incidentTabs.getSelectionModel().select(1);root.applyCss();root.layout();
                    var pane=(javafx.scene.layout.VBox)field(controller[0],"detailTimeline");
                    @SuppressWarnings("unchecked") TableView<SiemModels.TimelineEntry> table=(TableView<SiemModels.TimelineEntry>)pane.lookup(".table-view");
                    table.getSelectionModel().select(table.getItems().stream().filter(item->"ELK".equals(item.kind())).findFirst().orElseThrow());
                    root.applyCss();root.layout();
                    TabPane tabs=(TabPane)pane.lookup(".tab-pane");assertNotNull(tabs);tabs.getSelectionModel().select(1);root.applyCss();root.layout();
                    TextArea json=(TextArea)pane.lookup(".json-view");assertNotNull(json);assertTrue(json.getText().contains("\"_source\""));assertTrue(json.getText().contains("\"observer\""));assertFalse(json.getText().contains("={"));
                    snapshot(root,output.resolve("live-incident-"+tier+"-1100x760.png"));
                    snapshot(primary[0].getScene().getRoot(),output.resolve("live-queue-"+tier+"-1366x768.png"));
                    call(controller[0],"openIncident",String.class,ids[1]);assertSame(detail,field(controller[0],"incidentStage"));return null;});
                ready(()->field(controller[0],"draftNote")!=null&&ids[1].equals(field(controller[0],"openIncidentId")));
                fx(()->{primary[0].setWidth(1920);primary[0].setHeight(1080);snapshot(primary[0].getScene().getRoot(),output.resolve("live-queue-"+tier+"-1920x1080.png"));controller[0].dispose();assertFalse(detail.isShowing());assertNull(detail.getScene());return null;});
                completed.add(tier);
            }finally{
                try{api.logout().get(10,TimeUnit.SECONDS);}catch(Exception ignored){}
                fx(()->{if(controller[0]!=null)controller[0].dispose();if(primary[0]!=null)primary[0].close();return null;});
            }
        }
        assertEquals(List.of("L1","L2"),completed);
        Files.writeString(output.resolve("live-ui-result.private.json"),"{\"status\":\"LIVE_JAVAFX_L1_L2_PASS\",\"roles\":[\"L1\",\"L2\"],\"native_json\":true,\"single_reusable_stage\":true,\"session_ui_cleared\":true}");
    }
}
