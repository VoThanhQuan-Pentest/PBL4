package com.flarefitness.monitor.controller;

import com.flarefitness.monitor.api.SiemApiClient;
import com.flarefitness.monitor.model.SiemModels.LoginResponse;
import java.util.function.BiConsumer;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

public class LoginController {
    @FXML private TextField username;
    @FXML private PasswordField password;
    @FXML private Label errorLabel;
    @FXML private Button loginButton;
    private BiConsumer<SiemApiClient, com.flarefitness.monitor.model.SiemModels.User> onAuthenticated;

    public void setOnAuthenticated(
            BiConsumer<SiemApiClient, com.flarefitness.monitor.model.SiemModels.User> onAuthenticated) {
        this.onAuthenticated = onAuthenticated;
    }

    @FXML
    private void login() {
        errorLabel.setText("");
        if (username.getText().isBlank() || password.getText().isBlank()) {
            errorLabel.setText("Nhập username và password để tiếp tục.");
            return;
        }
        final SiemApiClient api;
        try {
            api = new SiemApiClient(SiemApiClient.configuredOrigin());
        } catch (IllegalArgumentException exception) {
            errorLabel.setText(exception.getMessage());
            return;
        }
        setBusy(true);
        api.login(username.getText().trim(), password.getText())
                .whenComplete((response, failure) -> Platform.runLater(() -> {
                    setBusy(false);
                    password.clear();
                    if (failure != null) {
                        errorLabel.setText("Đăng nhập thất bại: " + DashboardController.message(failure));
                        return;
                    }
                    if (!allowed(response)) {
                        api.logout();
                        errorLabel.setText("Cần tài khoản Administrator, Security analyst, SOC L1 hoặc SOC L2.");
                        return;
                    }
                    onAuthenticated.accept(api, response.user());
                }));
    }

    private boolean allowed(LoginResponse response) {
        return response!=null && !"OTHER".equals(com.flarefitness.monitor.model.SiemModels.socRole(response.user()));
    }

    private void setBusy(boolean busy) {
        loginButton.setDisable(busy);
        loginButton.setText(busy ? "Đang xác thực…" : "Đăng nhập");
    }
}
