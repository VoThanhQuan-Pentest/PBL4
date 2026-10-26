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
    @FXML private javafx.scene.layout.VBox credentialsGroup;
    @FXML private TextField username;
    @FXML private PasswordField password;
    @FXML private Label errorLabel;
    @FXML private Button loginButton;
    @FXML private TextField otpCode;
    @FXML private Label otpHint;
    @FXML private Button restartButton;
    private SiemApiClient pendingApi;
    private String challengeId;
    private boolean busy;
    private BiConsumer<SiemApiClient, com.flarefitness.monitor.model.SiemModels.User> onAuthenticated;

    public void setOnAuthenticated(
            BiConsumer<SiemApiClient, com.flarefitness.monitor.model.SiemModels.User> onAuthenticated) {
        this.onAuthenticated = onAuthenticated;
    }

    @FXML
    private void login() {
        if (busy) return;
        errorLabel.setText("");
        if (challengeId != null) {
            if (!otpCode.getText().matches("[0-9]{6}")) {
                errorLabel.setText("Nhập mã OTP 6 chữ số.");
                return;
            }
            setBusy(true);
            final SiemApiClient api = pendingApi;
            api.verifyLoginOtp(challengeId, otpCode.getText())
                    .whenComplete((response, failure) -> Platform.runLater(() -> finishLogin(api, response, failure)));
            return;
        }
        if (username.getText().isBlank() || password.getText().isBlank()) {
            errorLabel.setText("Nhập username và password để tiếp tục.");
            return;
        }
        final SiemApiClient api;
        try { api = new SiemApiClient(SiemApiClient.configuredOrigin()); }
        catch (IllegalArgumentException exception) { errorLabel.setText(exception.getMessage()); return; }
        setBusy(true);
        api.beginLogin(username.getText().trim(), password.getText())
                .whenComplete((attempt, failure) -> Platform.runLater(() -> {
                    password.clear();
                    if (failure != null) { finishLogin(api, null, failure); return; }
                    if (attempt.challenge() == null) { finishLogin(api, attempt.session(), null); return; }
                    pendingApi = api;
                    credentialsGroup.setVisible(false); credentialsGroup.setManaged(false);
                    challengeId = attempt.challenge().challengeId();
                    otpHint.setText("Mã đã gửi đến " + attempt.challenge().emailMasked() + ". Hiệu lực 5 phút.");
                    otpHint.setVisible(true); otpHint.setManaged(true);
                    otpCode.setVisible(true); otpCode.setManaged(true);
                    restartButton.setVisible(true); restartButton.setManaged(true);
                    setBusy(false);
                    otpCode.requestFocus();
                }));
    }

    @FXML
    private void restartLogin() {
        if (busy) return;
        if (pendingApi != null) pendingApi.clearSession();
        pendingApi = null; challengeId = null;
        credentialsGroup.setVisible(true); credentialsGroup.setManaged(true);
        otpCode.clear(); password.clear(); errorLabel.setText("");
        otpHint.setVisible(false); otpHint.setManaged(false);
        otpCode.setVisible(false); otpCode.setManaged(false);
        restartButton.setVisible(false); restartButton.setManaged(false);
        setBusy(false); password.requestFocus();
    }

    private void finishLogin(SiemApiClient api, LoginResponse response, Throwable failure) {
        setBusy(false); password.clear(); otpCode.clear();
        if (failure != null) {
            errorLabel.setText("Đăng nhập thất bại: " + DashboardController.message(failure));
            return;
        }
        if (!allowed(response)) {
            api.logout(); restartLogin();
            errorLabel.setText("Cần tài khoản Administrator, Security analyst, SOC L1 hoặc SOC L2.");
            return;
        }
        pendingApi = null; challengeId = null;
        onAuthenticated.accept(api, response.user());
    }

    private boolean allowed(LoginResponse response) {
        return response!=null && response.user()!=null && !"OTHER".equals(com.flarefitness.monitor.model.SiemModels.socRole(response.user()));
    }

    private void setBusy(boolean busy) {
        this.busy = busy;
        loginButton.setDisable(busy);
        username.setDisable(busy || challengeId != null);
        password.setDisable(busy || challengeId != null);
        otpCode.setDisable(busy);
        restartButton.setDisable(busy);
        loginButton.setText(busy ? "Đang xác thực…" : challengeId == null ? "Đăng nhập" : "Xác minh OTP");
    }
}
