package com.flarefitness.monitor.ui;

import com.flarefitness.monitor.api.SiemApiClient;
import com.flarefitness.monitor.controller.DashboardController;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.scene.control.*;
import javafx.scene.layout.*;

/** Candidate recommendations are explicitly separate from the authoritative baseline guard. */
public final class AuthShadowAssessmentsPane extends VBox {
    private final TableView<Map<String,Object>> table=new TableView<>();
    private long generation;
    public AuthShadowAssessmentsPane(SiemApiClient api,String incident,Consumer<String> open){
        super(10);Label title=new Label("PILOT_ONLY / SHADOW — gợi ý điều tra, không tạo hold hoặc block");title.setWrapText(true);title.getStyleClass().add("stale-banner");
        TextField account=new TextField();account.setPromptText("Account ID (tùy chọn)");Label state=new Label();
        Button search=new Button("Tải 24 giờ gần nhất");
        for(String field:List.of("as_of","user_id","recommendation","status","context_class","model_manifest_sha256")){
            TableColumn<Map<String,Object>,String> column=new TableColumn<>(field);column.setPrefWidth(field.equals("context_class")?220:160);column.setCellValueFactory(row->new ReadOnlyObjectWrapper<>(Objects.toString(row.getValue().get(field),"—")));table.getColumns().add(column);
        }
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);table.setPlaceholder(new Label("Chưa có assessment; candidate có thể đang OFF hoặc thiếu coverage."));table.setPrefHeight(420);
        Button related=new Button("Mở incident liên quan");related.setOnAction(e->{var row=table.getSelectionModel().getSelectedItem();if(row!=null&&row.get("incident_id") instanceof String id)open.accept(id);});
        search.setOnAction(e->{long request=++generation;LocalDateTime to=LocalDateTime.now(ZoneOffset.UTC);state.setText("Đang tải…");
            api.authShadowAssessments(incident,account.getText().trim(),to.minusHours(24),to).whenComplete((rows,error)->Platform.runLater(()->{
                if(request!=generation)return;
                if(error!=null){state.setText(DashboardController.message(error));return;}
                table.getItems().setAll(rows);state.setText(rows.size()+" kết quả mới nhất (tối đa50) · nguồn model/workflow, không phải log ELK");
            }));});
        getChildren().addAll(title,new FlowPane(8,8,account,search,related),state,table);VBox.setVgrow(table,Priority.ALWAYS);search.fire();
    }
    public void dispose(){generation++;table.getItems().clear();}
}
