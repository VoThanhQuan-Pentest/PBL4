package com.flarefitness.monitor.controller;

import static org.junit.jupiter.api.Assertions.*;
import com.flarefitness.monitor.FlareSecurityApp;
import com.flarefitness.monitor.api.SiemApiClient;
import javafx.fxml.FXMLLoader;
import javafx.scene.*;
import javafx.stage.Stage;
import java.nio.file.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/** Keeps the actual new queue/incident workspace loaded while full-stack/model memory is sampled. */
@EnabledIfEnvironmentVariable(named="FLARE_SIEM_WORKSPACE_SOAK",matches="true")
class WorkspaceFullStackSoakTest {
    @Test @Timeout(3900)
    void newDesktopRemainsLoadedAndAuthenticatedForOneHour()throws Exception {
        LiveWorkspaceAcceptanceTest.toolkit();var api=new SiemApiClient("http://127.0.0.1:8089");
        var login=api.login(System.getenv("FLARE_SOC_L1_USERNAME"),System.getenv("FLARE_SOC_L1_PASSWORD")).get(15,TimeUnit.SECONDS);
        DashboardController[] controller=new DashboardController[1];Stage[] stage=new Stage[1];
        Path output=Path.of(System.getenv("FLARE_SIEM_LIVE_UI_OUTPUT"));Files.createDirectories(output);
        long start=System.nanoTime();int probes=0;
        try{
            LiveWorkspaceAcceptanceTest.fx(()->{var loader=new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));Parent root=loader.load();controller[0]=loader.getController();stage[0]=new Stage();var scene=new Scene(root,1366,768);scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());stage[0].setScene(scene);stage[0].show();controller[0].initializeSession(api,login.user());LiveWorkspaceAcceptanceTest.call(controller[0],"openIncident",String.class,System.getenv("FLARE_SIEM_SOAK_INCIDENT"));return null;});
            LiveWorkspaceAcceptanceTest.ready(()->LiveWorkspaceAcceptanceTest.field(controller[0],"draftNote")!=null);
            while(System.nanoTime()-start<TimeUnit.HOURS.toNanos(1)){
                if(probes==0||TimeUnit.NANOSECONDS.toSeconds(System.nanoTime()-start)>=probes*60L){
                    if(probes==30)api.login(System.getenv("FLARE_SOC_L1_USERNAME"),System.getenv("FLARE_SOC_L1_PASSWORD")).get(15,TimeUnit.SECONDS);
                    var status=api.status().get(15,TimeUnit.SECONDS);assertTrue(status.elasticsearchAvailable());
                    LiveWorkspaceAcceptanceTest.fx(()->{assertTrue(stage[0].isShowing());assertNotNull(LiveWorkspaceAcceptanceTest.field(controller[0],"signedInUser"));return null;});probes++;
                    Files.writeString(output.resolve("desktop-soak-progress.private.json"),"{\"status\":\"RUNNING\",\"seconds\":"+TimeUnit.NANOSECONDS.toSeconds(System.nanoTime()-start)+",\"http_probes\":"+probes+"}");
                }
                Thread.sleep(1000);
            }
            Files.writeString(output.resolve("desktop-soak-result.private.json"),"{\"status\":\"LIVE_NEW_DESKTOP_ONE_HOUR_PASS\",\"seconds\":"+TimeUnit.NANOSECONDS.toSeconds(System.nanoTime()-start)+",\"http_probes\":"+probes+"}");
        }finally{
            try{api.logout().get(10,TimeUnit.SECONDS);}catch(Exception ignored){}
            LiveWorkspaceAcceptanceTest.fx(()->{if(controller[0]!=null)controller[0].dispose();if(stage[0]!=null)stage[0].close();return null;});
        }
    }
}
