package com.flarefitness.monitor;

import com.flarefitness.monitor.api.SiemApiClient;
import com.flarefitness.monitor.controller.DashboardController;
import com.flarefitness.monitor.controller.LoginController;
import com.flarefitness.monitor.model.SiemModels.User;
import java.io.IOException;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class FlareSecurityApp extends Application {
    private static Stage primaryStage;

    @Override
    public void start(Stage stage) throws IOException {
        primaryStage = stage;
        stage.setTitle("Flare Security Monitor");
        showLogin();
        stage.show();
    }

    public static void showLogin() throws IOException {
        primaryStage.setOnCloseRequest(null);
        primaryStage.setFullScreen(false);primaryStage.setMaximized(false);primaryStage.setResizable(false);
        FXMLLoader loader = new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/login.fxml"));
        Parent root = loader.load();
        LoginController controller = loader.getController();
        controller.setOnAuthenticated(FlareSecurityApp::showDashboard);
        primaryStage.setMinWidth(480);primaryStage.setMinHeight(480);
        setScene(root, 640, 560);
        Stage loginStage=primaryStage;Scene loginScene=loginStage.getScene();
        Runnable compact=()->{
            if(loginStage.getScene()!=loginScene)return;
            loginStage.setFullScreen(false);loginStage.setMaximized(false);
            var bounds=javafx.stage.Screen.getPrimary().getVisualBounds();
            loginStage.setWidth(Math.min(640,bounds.getWidth()));loginStage.setHeight(Math.min(560,bounds.getHeight()));loginStage.centerOnScreen();
        };
        javafx.beans.value.ChangeListener<Boolean> nativeState=(observable,old,value)->{
            if(value&&loginStage.getScene()==loginScene)javafx.application.Platform.runLater(compact);
        };
        loginStage.maximizedProperty().addListener(nativeState);loginStage.fullScreenProperty().addListener(nativeState);
        loginStage.sceneProperty().addListener(new javafx.beans.value.ChangeListener<Scene>(){
            @Override public void changed(javafx.beans.value.ObservableValue<? extends Scene> observable,Scene old,Scene next){
                if(next!=loginScene){loginStage.maximizedProperty().removeListener(nativeState);loginStage.fullScreenProperty().removeListener(nativeState);loginStage.sceneProperty().removeListener(this);}
            }
        });
        compact.run();javafx.application.Platform.runLater(compact);
    }

    public static void showDashboard(SiemApiClient apiClient, User user) {
        try {
            FXMLLoader loader = new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));
            Parent root = loader.load();
            DashboardController controller = loader.getController();
            controller.initializeSession(apiClient, user);
            primaryStage.setResizable(true);primaryStage.setMinWidth(1000);primaryStage.setMinHeight(680);
            primaryStage.setOnCloseRequest(event -> controller.dispose());
            setScene(root, 1440, 900);
        } catch (IOException exception) {
            throw new IllegalStateException("Cannot open dashboard", exception);
        }
    }

    private static void setScene(Parent root, double width, double height) {
        Scene scene = new Scene(root, width, height);
        scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());
        primaryStage.setScene(scene);
        var bounds=javafx.stage.Screen.getPrimary().getVisualBounds();
        primaryStage.setWidth(Math.min(width,bounds.getWidth()));
        primaryStage.setHeight(Math.min(height,bounds.getHeight()));
        primaryStage.centerOnScreen();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
