package com.flarefitness.monitor.controller;

import com.flarefitness.monitor.model.SiemModels;

import static org.junit.jupiter.api.Assertions.*;
import com.flarefitness.monitor.FlareSecurityApp;
import com.flarefitness.monitor.api.SiemApiClient;
import java.nio.file.*;
import java.util.concurrent.TimeUnit;
import javafx.fxml.FXMLLoader;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.input.*;
import javafx.stage.Stage;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

@EnabledIfEnvironmentVariable(named="FLARE_SIEM_LIVE_PRECISION_UI",matches="true")
class LiveEvidencePrecisionTest {
    @BeforeAll static void toolkit(){LiveWorkspaceAcceptanceTest.toolkit();}
    @SuppressWarnings({"rawtypes","unchecked"})
    static TreeItem<?> child(TreeTableView<?> tree,TreeItem<?> parent,String name){
        TreeTableColumn column=tree.getColumns().getFirst();
        return parent.getChildren().stream().filter(item->name.equals(column.getCellData((TreeItem)item))).findFirst().orElseThrow();
    }
    @Test void liveReputationKeepsProviderContextBoundToTheRequestedIp()throws Exception{
        SiemApiClient api=new SiemApiClient("http://127.0.0.1:8089");
        var login=api.login(System.getenv("FLARE_SOC_L1_USERNAME"),System.getenv("FLARE_SOC_L1_PASSWORD")).get(15,TimeUnit.SECONDS);
        DashboardController[] controller=new DashboardController[1];Stage[] primary=new Stage[1];
        try{
            LiveWorkspaceAcceptanceTest.fx(()->{FXMLLoader loader=new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));Parent root=loader.load();controller[0]=loader.getController();primary[0]=new Stage();Scene scene=new Scene(root,1366,768);scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());primary[0].setScene(scene);primary[0].show();controller[0].initializeSession(api,login.user());
                var method=DashboardController.class.getDeclaredMethod("showGeoIntelligence");method.setAccessible(true);method.invoke(controller[0]);root.applyCss();root.layout();TabPane tabs=(TabPane)root.lookup(".tab-pane");tabs.getSelectionModel().select(1);root.applyCss();root.layout();
                TextField ip=(TextField)root.lookup(".text-field");ip.setText("8.8.8.8");root.lookupAll(".button").stream().filter(n->n instanceof Button b&&"Lookup cached intelligence".equals(b.getText())).map(Button.class::cast).findFirst().orElseThrow().fire();return null;});
            LiveWorkspaceAcceptanceTest.ready(()->primary[0].getScene().getRoot().lookupAll(".note-card").size()==2);
            LiveWorkspaceAcceptanceTest.fx(()->{Parent root=primary[0].getScene().getRoot();assertTrue(root.lookupAll(".note-card").stream().allMatch(n->n instanceof Label label&&label.getText().contains("8.8.8.8")&&label.getText().contains("Abuse score")&&label.getText().contains("Observed UTC")));
                TextField ip=(TextField)root.lookup(".text-field");Button button=root.lookupAll(".button").stream().filter(n->n instanceof Button b&&"Lookup cached intelligence".equals(b.getText())).map(Button.class::cast).findFirst().orElseThrow();button.fire();ip.setText("10.23.45.67");return null;});
            Thread.sleep(500);
            LiveWorkspaceAcceptanceTest.fx(()->{assertTrue(primary[0].getScene().getRoot().lookupAll(".note-card").isEmpty(),"A late prior-IP response must not render for the edited IP");return null;});
        }finally{
            try{api.logout().get(10,TimeUnit.SECONDS);}catch(Exception ignored){}
            LiveWorkspaceAcceptanceTest.fx(()->{if(controller[0]!=null)controller[0].dispose();if(primary[0]!=null)primary[0].close();return null;});
        }
    }
    @Test @SuppressWarnings({"rawtypes","unchecked"})
    void realElkNumbersUnicodeAndNestedFieldsStayExactInFieldsJsonAndCopy()throws Exception{
        SiemApiClient api=new SiemApiClient("http://127.0.0.1:8089");
        var login=api.login(System.getenv("FLARE_SOC_L1_USERNAME"),System.getenv("FLARE_SOC_L1_PASSWORD")).get(15,TimeUnit.SECONDS);
        String id=System.getenv("FLARE_SIEM_PRECISION_CASE_ID");Path output=Path.of(System.getenv("FLARE_SIEM_LIVE_UI_OUTPUT"));
        DashboardController[] controller=new DashboardController[1];Stage[] primary=new Stage[1];
        try{
            LiveWorkspaceAcceptanceTest.fx(()->{FXMLLoader loader=new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));Parent root=loader.load();controller[0]=loader.getController();primary[0]=new Stage();
                Scene scene=new Scene(root,1366,768);scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());primary[0].setScene(scene);primary[0].show();controller[0].initializeSession(api,login.user());LiveWorkspaceAcceptanceTest.call(controller[0],"openIncident",String.class,id);return null;});
            LiveWorkspaceAcceptanceTest.ready(()->LiveWorkspaceAcceptanceTest.field(controller[0],"draftNote")!=null);
            LiveWorkspaceAcceptanceTest.ready(()->{Parent pane=(Parent)LiveWorkspaceAcceptanceTest.field(controller[0],"detailTimeline");return pane.lookupAll(".table-view").stream().anyMatch(node->node instanceof TableView<?> table&&table.getItems().stream().anyMatch(item->item instanceof SiemModels.TimelineEntry entry&&"ELK".equals(entry.kind())));});
            LiveWorkspaceAcceptanceTest.fx(()->{
                Stage window=(Stage)LiveWorkspaceAcceptanceTest.field(controller[0],"incidentStage");Parent root=window.getScene().getRoot();root.applyCss();root.layout();
                ((TabPane)root.lookup("#incident-tabs")).getSelectionModel().select(1);root.applyCss();root.layout();
                Parent pane=(Parent)LiveWorkspaceAcceptanceTest.field(controller[0],"detailTimeline");@SuppressWarnings("unchecked") TableView<SiemModels.TimelineEntry> table=(TableView<SiemModels.TimelineEntry>)pane.lookup(".table-view");table.getSelectionModel().select(table.getItems().stream().filter(item->"ELK".equals(item.kind())).findFirst().orElseThrow());root.applyCss();root.layout();
                TreeTableView tree=(TreeTableView)pane.lookup(".tree-table-view");assertNotNull(tree);
                TreeItem acceptance=(TreeItem)child(tree,tree.getRoot(),"acceptance");int row=tree.getRow(acceptance);tree.getSelectionModel().select(row);tree.getFocusModel().focus(row,(TreeTableColumn)tree.getColumns().getFirst());tree.requestFocus();
                tree.fireEvent(new KeyEvent(KeyEvent.KEY_PRESSED,"","",KeyCode.RIGHT,false,false,false,false));assertTrue(acceptance.isExpanded(),"Object expands with keyboard");
                TreeTableColumn values=(TreeTableColumn)tree.getColumns().get(2);
                assertEquals("123456789012345678901234567890",values.getCellData((TreeItem)child(tree,acceptance,"huge")));
                assertEquals("0.123456789012345678901234567890",values.getCellData((TreeItem)child(tree,acceptance,"decimal")));
                TreeItem nested=(TreeItem)child(tree,acceptance,"nested");nested.setExpanded(true);TreeItem array=(TreeItem)child(tree,nested,"array");array.setExpanded(true);assertEquals(5,array.getChildren().size());
                assertEquals("null",values.getCellData((TreeItem)array.getChildren().get(0)));assertEquals("true",values.getCellData((TreeItem)array.getChildren().get(1)));
                TabPane tabs=(TabPane)pane.lookup(".tab-pane");tabs.getSelectionModel().select(1);root.applyCss();root.layout();
                TextArea json=(TextArea)pane.lookup(".json-view");assertTrue(json.getText().contains("0.123456789012345678901234567890"));assertTrue(json.getText().contains("123456789012345678901234567890"));assertTrue(json.getText().contains("Tiếng Việt"));assertTrue(json.getText().contains("dotted.key"));
                Button copy=pane.lookupAll(".button").stream().filter(node->node instanceof Button button&&"Copy hit".equals(button.getText())).map(Button.class::cast).findFirst().orElseThrow();copy.fire();assertEquals(json.getText(),Clipboard.getSystemClipboard().getString());
                LiveWorkspaceAcceptanceTest.snapshot(root,output.resolve("live-exact-native-json.private.png"));
                Files.writeString(output.resolve("live-precision-ui-result.private.json"),"{\"status\":\"LIVE_JAVAFX_EXACT_FIELDS_JSON_COPY_PASS\",\"keyboard_expansion\":true,\"array_order\":true,\"unicode\":true,\"exact_numbers\":true}");return null;
            });
        }finally{
            try{api.logout().get(10,TimeUnit.SECONDS);}catch(Exception ignored){}
            LiveWorkspaceAcceptanceTest.fx(()->{if(controller[0]!=null)controller[0].dispose();if(primary[0]!=null)primary[0].close();return null;});
        }
    }
}
