package com.flarefitness.monitor.ui;

import com.flarefitness.monitor.api.SiemApiClient;
import com.flarefitness.monitor.model.SiemModels;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.scene.control.*;
import javafx.scene.layout.*;

/** Explicit-refresh SOC view: never discards an analyst's in-progress reason on a timer. */
public final class PostloginDecisionsPane extends VBox {
    private final SiemApiClient api;
    private final SiemModels.User user;
    private final Consumer<String> openIncident;
    private final String incidentId;
    private final Label status=new Label("Loading policy…"),error=new Label();
    private final TableView<SiemModels.PostloginDecision> table=new TableView<>();
    private final VBox detail=new VBox(8);
    private final Button previous=new Button("Previous"),next=new Button("Next"),refresh=new Button("Refresh");
    private int page;
    private long generation;
    public PostloginDecisionsPane(SiemApiClient api,SiemModels.User user,String incidentId,Consumer<String> openIncident) {
        super(12);this.api=api;this.user=user;this.incidentId=incidentId;this.openIncident=openIncident;
        status.setWrapText(true);error.setWrapText(true);error.getStyleClass().add("error-text");
        table.getColumns().add(column("Time",d->d.createdAt()));
        table.getColumns().add(column("Account",SiemModels.PostloginDecision::userId));
        table.getColumns().add(column("Operation",SiemModels.PostloginDecision::operation));
        table.getColumns().add(column("Mode",SiemModels.PostloginDecision::mode));
        table.getColumns().add(column("Decision",SiemModels.PostloginDecision::decision));
        table.getColumns().add(column("Outcome",SiemModels.PostloginDecision::outcome));
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.setPrefHeight(230);table.setPlaceholder(new Label("No recorded decisions in this scope."));
        table.getSelectionModel().selectedItemProperty().addListener((o,a,b)->{if(b!=null)load(b.id());});
        previous.setOnAction(e->{if(page>0){page--;refresh();}});
        next.setOnAction(e->{page++;refresh();});refresh.setOnAction(e->refresh());
        getChildren().addAll(status,new HBox(8,refresh,previous,next),error,table,detail);
        refresh();
    }
    private <T> TableColumn<SiemModels.PostloginDecision,T> column(String label,java.util.function.Function<SiemModels.PostloginDecision,T> f) {
        var column=new TableColumn<SiemModels.PostloginDecision,T>(label);
        column.setCellValueFactory(c->new ReadOnlyObjectWrapper<>(f.apply(c.getValue())));return column;
    }
    private void refresh() {
        long request=++generation;refresh.setDisable(true);error.setText("");
        api.postloginPolicy().thenCombine(api.postloginDecisions(incidentId,page),(policy,rows)->new Object[]{policy,rows})
                .whenComplete((value,failure)->Platform.runLater(()->{
                    if(request!=generation)return;refresh.setDisable(false);
                    if(failure!=null){error.setText(message(failure));return;}
                    var policy=(SiemModels.PostloginPolicy)value[0];
                    @SuppressWarnings("unchecked") var rows=(SiemModels.Page<SiemModels.PostloginDecision>)value[1];
                    status.setText(policy.scope()+" · "+policy.mode()+" · OTP required · maximum hold "+policy.maximumHoldSeconds()
                            +"s\n"+policy.provenance()+" · operator hold "+policy.operatorHold()+" · model "+policy.modelVersion());
                    table.getItems().setAll(rows.content());previous.setDisable(page==0);next.setDisable(!rows.hasNext());
                    detail.getChildren().clear();
                }));
    }
    private void load(String id) {
        refresh.setDisable(false);
        long request=++generation;detail.getChildren().setAll(label("Loading decision…"));
        api.postloginDecision(id).whenComplete((value,failure)->Platform.runLater(()->{
            if(request!=generation)return;
            if(failure!=null){detail.getChildren().setAll(label(message(failure)));return;}
            render(value);
        }));
    }
    private void render(SiemModels.PostloginDetail d) {
        var s=d.summary();
        var reason=new TextArea();reason.setPromptText("Reason (10–1000 characters); never enter OTPs or passwords.");reason.setPrefRowCount(3);
        var verdict=new ComboBox<String>();verdict.getItems().addAll("LEGITIMATE","CONFIRMED_ABUSE","UNDETERMINED");verdict.setValue("UNDETERMINED");
        var release=new Button("Release temporary hold");var review=new Button("Save review");var linked=new Button("Open linked incident");
        String role=SiemModels.socRole(user);
        boolean reviewer="L2".equals(role)||"ADMIN".equals(role);
        release.setDisable(!reviewer||!d.holdActive());review.setDisable(!reviewer);linked.setDisable(s.incidentId()==null);
        linked.setOnAction(e->openIncident.accept(s.incidentId()));
        release.setOnAction(e->mutate(api.releasePostloginHold(s.id(),s.version(),reason.getText()),release,review));
        review.setOnAction(e->mutate(api.reviewPostloginDecision(s.id(),s.version(),verdict.getValue(),reason.getText()),release,review));
        var reviews=new VBox(6);
        d.reviews().forEach(r->reviews.getChildren().add(label(r.createdAt()+" · "+r.actorId()+" · "+r.verdict()+"\n"+r.reason())));
        var features=new TitledPane("Observed numeric snapshot (before execution)",label(d.snapshot().toString()));features.setExpanded(false);
        detail.getChildren().setAll(label(s.id()+" · "+s.decision()+" / "+s.outcome()),
                label("Context "+s.context()+" · baseline "+d.baselineEstablished()+" · trusted windows "+d.trustedWindowCount()
                        +"\nNormal percentile "+s.normalPercentile()+" (not attack probability)\nHold active "+d.holdActive()+" · until "+s.holdExpiresAt()),
                label(String.join("\n",d.reasons())),label("Evidence "+d.evidence()),
                label("Model "+d.modelVersion()+"\nBundle SHA "+d.modelSha256()+"\nManifest SHA "+d.manifestSha256()
                        +"\nPolicy "+d.policyId()+" v"+d.policyVersion()),features,linked,
                label("L1: inspect and add notes in the incident. L2: claim the escalated incident before releasing or reviewing."),
                reason,verdict,new HBox(8,release,review),label("Release: "+d.releasedAt()+" / "+d.releasedBy()+" / "+d.releaseReason()),reviews);
    }
    private void mutate(CompletableFuture<SiemModels.PostloginDetail> future,Button release,Button review) {
        release.setDisable(true);review.setDisable(true);long request=++generation;error.setText("");
        future.whenComplete((value,failure)->Platform.runLater(()->{
            if(request!=generation)return;
            if(failure!=null){error.setText(message(failure)+" Refresh before retrying.");refresh.setDisable(false);return;}
            render(value);
        }));
    }
    private Label label(String value) { var label=new Label(value);label.setWrapText(true);return label; }
    private String message(Throwable failure) {
        while(failure.getCause()!=null)failure=failure.getCause();return failure.getMessage()==null?"Request failed.":failure.getMessage();
    }
}
