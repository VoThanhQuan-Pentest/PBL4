package com.flarefitness.monitor.controller;

import com.flarefitness.monitor.FlareSecurityApp;
import com.flarefitness.monitor.api.SiemApiClient;
import com.flarefitness.monitor.model.SiemModels;
import com.flarefitness.monitor.ui.OverviewPane;
import com.flarefitness.monitor.ui.EvidenceBrowserPane;
import com.flarefitness.monitor.ui.InvestigationTimelinePane;
import com.flarefitness.monitor.ui.IncidentPresentation;
import com.flarefitness.monitor.ui.AuthShadowAssessmentsPane;
import javafx.stage.Stage;
import javafx.scene.Scene;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.input.KeyCode;
import com.flarefitness.monitor.ui.AccountWatchPane;
import com.flarefitness.monitor.ui.PostloginDecisionsPane;
import com.flarefitness.monitor.ui.BehaviorSignalSummary;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.fxml.FXML;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.SplitPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.TextInputDialog;
import javafx.scene.control.TitledPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

public class DashboardController {
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("dd/MM HH:mm:ss");
    @FXML private VBox contentHost;
    @FXML private Label pageTitle;
    @FXML private Label userLabel;
    @FXML private Label connectionLabel;
    @FXML private Label refreshedLabel;
    private SiemApiClient api;
    private SiemModels.User signedInUser;
    private ScheduledExecutorService refreshExecutor;
    private boolean signingOut;
    private String currentView = "overview";
    private SiemModels.UebaTrainingJob lastTrainingJob;
    private int trainingPage;
    private int shadowPage;
    private long settingsGeneration;
    private CompletableFuture<?> settingsRequest;
    private final Map<String, String> pendingRevocationIds = new HashMap<>();

    private OverviewPane overviewPane;
    private CompletableFuture<?> overviewRequest;
    private long overviewGeneration;
    private LocalDateTime overviewFrom;
    private LocalDateTime overviewTo;
    private AccountWatchPane watchPane;
    private CompletableFuture<?> watchRequest;
    private long watchGeneration;
    private long accountDetailGeneration;

    private TextField incidentSearch;
    private ComboBox<FilterOption> severityFilter;
    private ComboBox<FilterOption> statusFilter;
    private ComboBox<FilterOption> classificationFilter;
    private ComboBox<FilterOption> sortFilter;
    private ComboBox<FilterOption> queueTierFilter;
    private ComboBox<FilterOption> originFilter;
    private CheckBox mineFilter;
    private TableView<SiemModels.Incident> incidentTable;
    private VBox incidentDetail;
    private Stage incidentStage;
    private String openIncidentId;
    private long detailGeneration;
    private InvestigationTimelinePane detailTimeline;
    private AuthShadowAssessmentsPane authShadowPane;
    private TextArea draftNote;
    private Label draftError;
    private boolean noteSaving;
    private EvidenceBrowserPane detailEvidence;
    private EvidenceBrowserPane searchEvidence;
    private Label incidentError;
    private Label pageLabel;
    private Button previousPage;
    private Button nextPage;
    private final Map<String,SiemModels.InvestigationQueueEntry> queueSummaries=new HashMap<>();
    private int blockPage;
    private int incidentPage;
    private int incidentTotalPages;
    private String incidentScope = "OPEN";
    private LocalDateTime incidentFrom;
    private LocalDateTime incidentTo;
    private String pendingIncidentId;
    private CompletableFuture<?> incidentRequest;
    private long incidentGeneration;
    private boolean configuringFilters;
    private long headerGeneration;
    private CompletableFuture<?> headerRequest;

    public void initializeSession(SiemApiClient api, SiemModels.User user) {
        this.api = api;
        this.signedInUser = user;
        userLabel.setText(user.hoTen() + "  ·  " + user.role());
        api.setOnSessionExpired(() -> Platform.runLater(() -> {
            if(signingOut)return;dispose();
            try {FlareSecurityApp.showLogin();}catch(Exception e){throw new IllegalStateException(e);}
        }));
        if(defaultQueueTier()==null) showOverview();else showAlerts();
        refreshHeaderHealth();
        refreshExecutor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "flare-siem-refresh");
            thread.setDaemon(true);
            return thread;
        });
        refreshExecutor.scheduleWithFixedDelay(
                () -> Platform.runLater(this::refreshCurrentView), 15, 15, TimeUnit.SECONDS);
    }

    @FXML private void showOverview() {
        currentView = "overview";
        pageTitle.setText("Security overview");
        cancelIncidentRequest();
        overviewPane = new OverviewPane(
                this::openChartFilter,
                this::openPriorityIncident,
                this::refreshOverview,
                this::refreshOverview);
        ScrollPane scroll = new ScrollPane(overviewPane);
        scroll.setFitToWidth(true);
        scroll.getStyleClass().add("overview-scroll");
        setContent(scroll);
        refreshOverview();
    }

    @FXML private void showAlerts() {
        openIncidentQueue(null, null, null, null, null);
    }

    @FXML private void showWatchlist() {
        currentView = "watchlist";
        pageTitle.setText("Account watchlist");
        cancelDashboardRequests();
        watchPane = new AccountWatchPane(this::refreshWatchlist, this::loadAccountBehavior);
        setContent(watchPane);
        refreshWatchlist();
    }

    @FXML private void showPostloginDecisions() { showPostloginDecisions(null); }

    private void showPostloginDecisions(String incidentId) {
        currentView = "postlogin-decisions";
        pageTitle.setText("Post-login decisions · project lab");
        cancelDashboardRequests();
        var pane = new PostloginDecisionsPane(api, signedInUser, incidentId, id -> {
            pendingIncidentId = id;
            showAlerts();
            openIncident(id);
        });
        var scroll = new ScrollPane(pane);scroll.setFitToWidth(true);
        if(authShadowPane!=null)authShadowPane.dispose();
        authShadowPane=new AuthShadowAssessmentsPane(api,incidentId,this::openIncident);
        Tab baseline=new Tab("Baseline / guard hiện tại",scroll),shadow=new Tab("Candidate / shadow",authShadowPane);baseline.setClosable(false);shadow.setClosable(false);
        setContent(new TabPane(baseline,shadow));
    }

    private void refreshWatchlist() {
        if (!"watchlist".equals(currentView) || watchPane == null) return;
        long generation = ++watchGeneration;
        if (watchRequest != null) watchRequest.cancel(true);
        AccountWatchPane target = watchPane;
        target.loading();
        LocalDateTime to = LocalDateTime.now(ZoneOffset.UTC);
        watchRequest = api.watchlist(to.minusHours(24), to, target.view(), target.page(), 50)
                .whenComplete((page, failure) -> Platform.runLater(() -> {
            if (!"watchlist".equals(currentView) || generation != watchGeneration || target != watchPane) return;
            if (failure != null) target.error(message(failure));
            else {
                target.accept(page);
                markRefreshed();
            }
        }));
    }

    @FXML private void showSignatures() {
        currentView = "signatures";
        pageTitle.setText("Attack signatures");
        cancelDashboardRequests();
        setContent(stateLabel("Loading reviewed attack patterns…", "muted"));
        api.signatures().thenCombine(api.preventionStatus(), (page, status) ->
                new SignatureView(page.content(), status))
                .whenComplete((data, failure) -> Platform.runLater(() -> {
                    if (!"signatures".equals(currentView)) return;
                    if (failure != null) showError(failure);
                    else {
                        ScrollPane scroll = new ScrollPane(signaturePanel(data));
                        scroll.setFitToWidth(true);
                        setContent(scroll);
                        markRefreshed();
                    }
                }));
    }

    private Node signaturePanel(SignatureView data) {
        VBox root = new VBox(12);
        root.getStyleClass().add("panel");
        Label status = stateLabel("Gateway policy " + data.status.publishedVersion()
                + " · applied " + (data.status.appliedVersion() == null
                        ? "pending" : data.status.appliedVersion())
                + " · " + data.status.gatewayState(), "detail-meta");
        TableView<SiemModels.AttackSignature> table = new TableView<>();
        table.setPrefHeight(310);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.getColumns().add(column("Pattern", 190, SiemModels.AttackSignature::id));
        table.getColumns().add(column("Type", 100, SiemModels.AttackSignature::kind));
        table.getColumns().add(column("Match", 155, item -> safe(item.matchValue())));
        table.getColumns().add(column("Severity", 100, SiemModels.AttackSignature::severity));
        table.getColumns().add(column("State", 100, SiemModels.AttackSignature::status));
        table.getColumns().add(column("Source case", 200,
                item -> safe(item.sourceIncidentId())));
        table.getItems().setAll(data.signatures);
        ComboBox<String> kind = filterBox("PATH_EXACT", "PATH_PREFIX", "SQLI", "XSS", "TRAVERSAL");
        ComboBox<String> severity = filterBox("HIGH", "URGENT", "MEDIUM", "LOW");
        TextField method = new TextField();
        method.setPromptText("Optional HTTP method");
        TextField scope = new TextField();
        scope.setPromptText("Optional path scope");
        TextField value = new TextField();
        value.setPromptText("Literal path for PATH_* types");
        Label feedback = stateLabel("A pattern does not block traffic until L2/Admin tests and activates it.",
                "muted");
        Button create = actionButton("Propose pattern", () -> {
            feedback.setText("Creating draft…");
            api.createSignature(kind.getValue(), method.getText(), scope.getText(),
                            value.getText(), severity.getValue())
                    .whenComplete((item, failure) -> Platform.runLater(() -> {
                        if (failure != null) feedback.setText(message(failure));
                        else showSignatures();
                    }));
        });
        HBox form = new HBox(8, kind, severity, method, scope, value, create);
        HBox.setHgrow(value, Priority.ALWAYS);
        root.getChildren().addAll(status, table, stateLabel("PROPOSE A PATTERN", "eyebrow"),
                form, feedback);
        if (isHigherTierUser()) {
            Button test = actionButton("Test selected", () -> {
                SiemModels.AttackSignature item = table.getSelectionModel().getSelectedItem();
                if (item == null) { feedback.setText("Select a pattern first."); return; }
                feedback.setText("Testing with synthetic attack and benign examples…");
                api.testDefaultSignature(item).whenComplete((result, failure) -> Platform.runLater(() -> {
                    if (failure != null) feedback.setText(message(failure));
                    else if (!result.passed()) feedback.setText(
                            "Test failed: " + result.passedCases() + "/" + result.totalCases());
                    else showSignatures();
                }));
            });
            Button activate = actionButton("Activate selected", () -> {
                SiemModels.AttackSignature item = table.getSelectionModel().getSelectedItem();
                if (item == null) { feedback.setText("Select a pattern first."); return; }
                Alert confirmation = new Alert(Alert.AlertType.CONFIRMATION,
                        "Enforce tested pattern " + item.id() + " at the gateway?",
                        ButtonType.CANCEL, ButtonType.OK);
                confirmation.setHeaderText("Confirm gateway policy change");
                if (confirmation.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) return;
                api.activateSignature(item).whenComplete((result, failure) -> Platform.runLater(() -> {
                    if (failure != null) feedback.setText(message(failure)); else showSignatures();
                }));
            });
            Button disable = secondaryButton("Disable selected", () -> {
                SiemModels.AttackSignature item = table.getSelectionModel().getSelectedItem();
                if (item == null) { feedback.setText("Select a pattern first."); return; }
                api.disableSignature(item).whenComplete((result, failure) -> Platform.runLater(() -> {
                    if (failure != null) feedback.setText(message(failure)); else showSignatures();
                }));
            });
            root.getChildren().add(new HBox(8, test, activate, disable));

            ComboBox<String> attackMethod = filterBox("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD");
            ComboBox<String> benignMethod = filterBox("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD");
            TextField attackPath = new TextField();
            TextField benignPath = new TextField("/products/safe");
            attackPath.setPromptText("Synthetic path expected to match");
            benignPath.setPromptText("Synthetic path expected to pass");
            TextField attackBody = new TextField();
            TextField benignBody = new TextField();
            attackBody.setPromptText("Synthetic form body, optional");
            benignBody.setPromptText("Benign form body, optional");
            HBox attackRow = new HBox(8, attackMethod, attackPath, attackBody);
            HBox benignRow = new HBox(8, benignMethod, benignPath, benignBody);
            HBox.setHgrow(attackPath, Priority.ALWAYS);
            HBox.setHgrow(benignPath, Priority.ALWAYS);
            HBox.setHgrow(attackBody, Priority.ALWAYS);
            HBox.setHgrow(benignBody, Priority.ALWAYS);
            table.getSelectionModel().selectedItemProperty().addListener((ignored, old, selected) -> {
                if (selected == null) return;
                String selectedMethod = selected.httpMethod() == null
                        ? ("SQLI".equals(selected.kind()) || "XSS".equals(selected.kind()) ? "POST" : "GET")
                        : selected.httpMethod();
                attackMethod.setValue(selectedMethod);
                benignMethod.setValue(selectedMethod);
                attackBody.clear();
                benignBody.clear();
                String fixtureScope = selected.pathPrefix() == null
                        ? "/api/products" : selected.pathPrefix();
                switch (selected.kind()) {
                    case "PATH_EXACT" -> {
                        attackPath.setText(selected.matchValue());
                        benignPath.setText("/products/safe");
                    }
                    case "PATH_PREFIX" -> {
                        attackPath.setText(selected.matchValue() + "probe");
                        benignPath.setText("/products/safe");
                    }
                    case "SQLI" -> {
                        attackPath.setText(fixtureScope);
                        benignPath.setText(fixtureScope);
                        attackBody.setText("q=1%27+UNION+SELECT+password+FROM+users");
                        benignBody.setText("q=plain");
                    }
                    case "XSS" -> {
                        attackPath.setText(fixtureScope);
                        benignPath.setText(fixtureScope);
                        attackBody.setText("q=%3Cscript%3Ealert(1)%3C/script%3E");
                        benignBody.setText("q=plain");
                    }
                    case "TRAVERSAL" -> {
                        String base = selected.pathPrefix() == null ? "/" : selected.pathPrefix();
                        if (!base.endsWith("/")) base += "/";
                        attackPath.setText(base + "../../etc/passwd");
                        benignPath.setText(base + "products/safe");
                    }
                    default -> {
                        attackPath.setText(fixtureScope);
                        benignPath.setText(fixtureScope);
                    }
                }
            });
            Button customTest = actionButton("Run two fixtures", () -> {
                SiemModels.AttackSignature item = table.getSelectionModel().getSelectedItem();
                if (item == null) { feedback.setText("Select a pattern first."); return; }
                if (attackPath.getText().isBlank() || benignPath.getText().isBlank()) {
                    feedback.setText("Enter both synthetic paths.");
                    return;
                }
                List<Map<String, Object>> fixtures = List.of(
                        signatureFixture(attackMethod.getValue(), attackPath.getText(),
                                attackBody.getText(), true),
                        signatureFixture(benignMethod.getValue(), benignPath.getText(),
                                benignBody.getText(), false));
                feedback.setText("Testing matching and benign synthetic requests…");
                api.testSignature(item, fixtures).whenComplete((result, failure) -> Platform.runLater(() -> {
                    if (failure != null) feedback.setText(message(failure));
                    else if (!result.passed()) feedback.setText(
                            "Test failed: " + result.passedCases() + "/" + result.totalCases());
                    else showSignatures();
                }));
            });
            VBox customFixtures = new VBox(8,
                    stateLabel("Use synthetic paths and form bodies only. Include one matching request and one benign request.",
                            "muted"),
                    stateLabel("EXPECTED MATCH", "eyebrow"), attackRow,
                    stateLabel("EXPECTED PASS", "eyebrow"), benignRow, customTest);
            TitledPane fixtureEditor = new TitledPane("Custom signature test fixtures", customFixtures);
            fixtureEditor.setExpanded(false);
            root.getChildren().add(fixtureEditor);
        }
        return root;
    }

    private static Map<String, Object> signatureFixture(
            String method, String path, String body, boolean expectedMatch) {
        Map<String, Object> fixture = new HashMap<>();
        fixture.put("http_method", method);
        fixture.put("request_path", path.trim());
        fixture.put("request_body", body == null || body.isBlank() ? null : body);
        fixture.put("expected_match", expectedMatch);
        return fixture;
    }

    @FXML private void showIpIntelligence() {
        currentView = "ip-intelligence";
        pageTitle.setText("IP intelligence");
        cancelDashboardRequests();
        VBox panel = new VBox(12);
        panel.getStyleClass().add("panel");
        TextField ip = new TextField();
        ip.setPromptText("Public IPv4 or IPv6 address");
        Label feedback = stateLabel("Provider lookups run in the background; no key is stored in JavaFX.", "muted");
        TableView<SiemModels.IpIntelligence> table = new TableView<>();
        table.setPrefHeight(310);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.getColumns().add(column("Provider", 140, SiemModels.IpIntelligence::provider));
        table.getColumns().add(column("Status", 140, SiemModels.IpIntelligence::status));
        table.getColumns().add(column("Data", 100, SiemModels.IpIntelligence::dataProvenance));
        table.getColumns().add(column("Country", 90, value -> safe(value.countryCode())));
        table.getColumns().add(column("ASN", 110, value -> safe(value.asn())));
        table.getColumns().add(column("Organization", 220, value -> safe(value.asName())));
        table.getColumns().add(column("Anonymous", 110,
                value -> value.anonymousFlag() == null ? "Unavailable" : value.anonymousFlag() ? "Yes" : "No"));
        table.getColumns().add(column("Hosting", 90,
                value -> value.hostingFlag() == null ? "Unavailable" : value.hostingFlag() ? "Yes" : "No"));
        table.getColumns().add(column("Abuse score", 110,
                value -> value.abuseScore() == null ? "Unavailable" : value.abuseScore().toString()));
        table.getColumns().add(column("Reports", 90,
                value -> value.totalReports() == null ? "—" : value.totalReports().toString()));
        table.getColumns().add(column("Observed", 150, value -> safeTime(value.observedAt())));
        Button inspect = secondaryButton("Inspect cached result", () -> {
            if (ip.getText().isBlank()) { feedback.setText("Enter an IP address."); return; }
            api.ipIntelligence(ip.getText().trim())
                    .whenComplete((items, failure) -> Platform.runLater(() -> {
                        if (failure != null) feedback.setText(message(failure));
                        else {
                            table.getItems().setAll(items);
                            feedback.setText(items.isEmpty() ? "No result cached yet." :
                                    "Read provider timestamps before making a decision.");
                        }
                    }));
        });
        Button lookup = actionButton("Request lookup", () -> {
            if (ip.getText().isBlank()) { feedback.setText("Enter an IP address."); return; }
            api.requestIpLookup(ip.getText().trim(), "SOC_REQUEST")
                    .whenComplete((item, failure) -> Platform.runLater(() -> {
                        feedback.setText(failure == null ? "Lookup queued. Refresh the cached result shortly."
                                : message(failure));
                    }));
        });
        Button demo = secondaryButton(isAdminUser() ? "Seed labelled demo" : "View labelled demo", () -> {
            var result = isAdminUser() ? api.seedDemoIpIntelligence() : api.demoIpIntelligence();
            result.whenComplete((items, failure) -> Platform.runLater(() -> {
                if (failure != null) feedback.setText(message(failure));
                else {
                    table.getItems().setAll(items);
                    feedback.setText("DEMO_ONLY: TEST-NET fixture, not a real IPinfo/AbuseIPDB lookup.");
                }
            }));
        });
        api.preventionStatus().whenComplete((status, failure) -> Platform.runLater(() -> {
            if (!"ip-intelligence".equals(currentView)) return;
            if (failure == null) feedback.setText(
                    "IPinfo " + status.ipinfoState() + " · AbuseIPDB " + status.abuseIpDbState()
                            + " · missing fields mean unavailable, never safe.");
        }));
        HBox form = new HBox(8, ip, inspect, lookup, demo);
        HBox.setHgrow(ip, Priority.ALWAYS);
        panel.getChildren().addAll(form, feedback, table);
        setContent(panel);
    }

    @FXML private void showIpBlocks() {
        if(!"ip-blocks".equals(currentView))blockPage=0;
        currentView="ip-blocks";pageTitle.setText("Block IP");cancelDashboardRequests();
        setContent(stateLabel("Loading blocks, ledger and policy ACK…","muted"));
        long generation=settingsGeneration;
        api.blocksWithLedger(blockPage).whenComplete((data,failure)->Platform.runLater(()->{
            if(!"ip-blocks".equals(currentView)||signingOut||generation!=settingsGeneration)return;
            if(failure!=null){showError(failure);return;}
            VBox pane=new VBox(10,new javafx.scene.layout.FlowPane(8,8,secondaryButton("Signatures",this::showSignatures),
                secondaryButton("Model decisions",this::showPostloginDecisions)),
                stateLabel("Recurrence "+data.recurrenceMode()+" · Gateway "+data.policy().gatewayState()+" · published "+data.policy().publishedVersion()+" / ACK "+data.policy().appliedVersion(),"detail-meta"),
                ipBlocksPanel(data.blocks().content(),data));
            VBox.setVgrow(pane.getChildren().getLast(),Priority.ALWAYS);
            Button previous=secondaryButton("← Previous",()->{if(blockPage>0){blockPage--;showIpBlocks();}});
            Button next=secondaryButton("Next →",()->{if(data.blocks().hasNext()){blockPage++;showIpBlocks();}});
            previous.setDisable(data.blocks().page()==0);next.setDisable(!data.blocks().hasNext());
            pane.getChildren().add(new HBox(8,previous,stateLabel("Page "+(data.blocks().page()+1)+" / "+Math.max(1,data.blocks().totalPages())+" · "+data.blocks().totalElements()+" blocks","muted"),next));
            setContent(pane);markRefreshed();
        }));
    }

    private Node ipBlocksPanel(List<SiemModels.IpBlock> items,SiemModels.BlockWorkspace workspace) {
        VBox panel = new VBox(12);
        panel.getStyleClass().add("panel");
        TableView<SiemModels.IpBlock> table = new TableView<>();
        table.setPrefHeight(360);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.getColumns().add(column("IP", 160, SiemModels.IpBlock::ipAddress));
        table.getColumns().add(column("Source", 110, SiemModels.IpBlock::sourceType));
        table.getColumns().add(column("Reason", 340, SiemModels.IpBlock::reason));
        table.getColumns().add(column("Expires", 160, value -> value.expiresAt()==null?"Đến khi gỡ":safeTime(value.expiresAt())));
        table.getColumns().add(column("Revoked", 160, value -> safeTime(value.revokedAt())));
        table.getColumns().add(column("Gateway ACK",140,value->{
            var ledger=workspace.ledger().stream().filter(row->value.id().equals(row.get("block_id"))).findFirst().orElse(Map.of());
            Object version=ledger.get(value.revokedAt()==null?"published_policy_version":"revoke_policy_version");
            boolean applied=version instanceof Number number && workspace.policy().appliedVersion()!=null && workspace.policy().appliedVersion()>=number.longValue();
            if(value.revokedAt()!=null)return applied?"RELEASED":"PENDING_RELEASE";
            if(value.expiresAt()!=null&&!value.expiresAt().isAfter(LocalDateTime.now(ZoneOffset.UTC)))return "EXPIRED";
            return applied?"APPLIED":"PENDING";
        }));
        table.getColumns().add(column("Episode / strike",160,value->workspace.ledger().stream().filter(row->value.id().equals(row.get("block_id")))
                .map(row->row.get("strike_number")==null?"No recurrence strike":row.get("strike_number")+" · "+row.get("provenance")+(row.get("invalidated_at")==null?"":" · INVALIDATED")).findFirst().orElse("No recurrence strike")));
        table.getItems().setAll(items);
        Label feedback = stateLabel("Temporary blocks expire. UNTIL_REVOKED requires L2/Admin release. Pending policy is not applied.", "muted");
        panel.getChildren().addAll(table, feedback);
        if (isHigherTierUser()) {
            TextField ip = new TextField();
            ip.setPromptText("Public IP");
            TextField reason = new TextField();
            reason.setPromptText("Specific reason (10+ characters)");
            ComboBox<Integer> duration = filterBox(15, 60, 1440);
            Button block = actionButton("Block with expiry", () -> {
                if (ip.getText().isBlank() || reason.getText().trim().length() < 10) {
                    feedback.setText("Enter a public IP and a reason of at least 10 characters.");
                    return;
                }
                Alert confirmation = new Alert(Alert.AlertType.CONFIRMATION,
                        "Block " + ip.getText().trim() + " for " + duration.getValue()
                                + " minutes? Shared or mobile IPs may represent other users.",
                        ButtonType.CANCEL, ButtonType.OK);
                confirmation.setTitle("Confirm timed IP block");
                confirmation.setHeaderText("SOC L2 response");
                if (confirmation.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) return;
                api.createIpBlock(ip.getText().trim(), reason.getText().trim(),
                                duration.getValue(), null)
                        .whenComplete((value, failure) -> Platform.runLater(() -> {
                            if (failure != null) feedback.setText(message(failure)); else showIpBlocks();
                        }));
            });
            Button revoke = secondaryButton("Revoke selected", () -> {
                SiemModels.IpBlock selected = table.getSelectionModel().getSelectedItem();
                if (selected == null) { feedback.setText("Select a block first."); return; }
                TextInputDialog reasonDialog=new TextInputDialog();reasonDialog.setHeaderText("Lý do gỡ block (10–500 ký tự)");
                String releaseReason=reasonDialog.showAndWait().orElse("").trim();if(releaseReason.length()<10||releaseReason.length()>500){feedback.setText("A specific release reason is required.");return;}
                javafx.scene.control.ChoiceDialog<String> outcome=new javafx.scene.control.ChoiceDialog<>("RISK_ACCEPTED",List.of("RISK_ACCEPTED","FALSE_POSITIVE"));
                outcome.setHeaderText("RISK_ACCEPTED giữ strike; FALSE_POSITIVE vô hiệu hóa strike liên quan.");
                outcome.showAndWait().ifPresent(choice->{String key="revoke:"+selected.id()+":"+selected.version()+":"+releaseReason+":"+choice;
                    api.revokeBlock(selected,releaseReason,choice,pendingRevocationIds.computeIfAbsent(key,k->UUID.randomUUID().toString())).whenComplete((value,failure)->Platform.runLater(()->{
                        if(signingOut||!"ip-blocks".equals(currentView))return;
                        if(failure!=null)feedback.setText(message(failure));else{pendingRevocationIds.remove(key);showIpBlocks();}
                    }));
                });
            });
            HBox form = new HBox(8, ip, reason, duration, block, revoke);
            HBox.setHgrow(reason, Priority.ALWAYS);
            panel.getChildren().add(form);
        }
        return panel;
    }

    @FXML private void showLogs() {
        currentView="logs";pageTitle.setText("Incident queue · ELK Discover");cancelDashboardRequests();
        if(searchEvidence!=null)searchEvidence.dispose();
        if(authShadowPane!=null)authShadowPane.dispose();authShadowPane=null;
        searchEvidence=new EvidenceBrowserPane(api,null);searchEvidence.onIncident(id->{showAlerts();openIncident(id);});
        VBox pane=new VBox(10,secondaryButton("← Incident queue",this::showAlerts),searchEvidence);VBox.setVgrow(searchEvidence,Priority.ALWAYS);setContent(pane);
    }
    @FXML private void showGeoIntelligence() {
        currentView="geo-intelligence";pageTitle.setText("GeoIP & IP intelligence");cancelDashboardRequests();
        VBox geo=new VBox(8,stateLabel("Loading geographic data from ELK…","muted"));
        VBox intelligence=new VBox(10),reputationRows=new VBox(8);
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
                    +"\nCountry "+safe(item.countryCode())+" · ASN "+safe(item.asn())+" · "+safe(item.asName())
                    +"\nAbuse score "+(item.abuseScore()==null?"unavailable":item.abuseScore())+" · reports "+(item.totalReports()==null?"unavailable":item.totalReports())
                    +"\nAnonymous "+(item.anonymousFlag()==null?"unavailable":item.anonymousFlag())+" · hosting "+(item.hostingFlag()==null?"unavailable":item.hostingFlag())
                    +"\nObserved UTC "+safeTime(item.observedAt())+" · expires UTC "+safeTime(item.expiresAt()),"note-card"));
                feedback.setText(items.isEmpty()?"No cached public-IP intelligence for "+requestedIp:items.size()+" provider results for "+requestedIp);
            }));
        });
        Button refresh=secondaryButton("Request provider refresh",()->{
            String requestedIp=ip.getText().trim();long generation=lookupGeneration.incrementAndGet();
            api.requestIpLookup(requestedIp,"SOC_MANUAL_REVIEW").whenComplete((result,error)->Platform.runLater(()->{
                if(signingOut || !"geo-intelligence".equals(currentView) || generation!=lookupGeneration.get() || !requestedIp.equals(ip.getText().trim()))return;
                feedback.setText(error==null?"Lookup request accepted for "+requestedIp+". Load the cache for current provider status.":message(error));
            }));
        });
        intelligence.getChildren().addAll(new javafx.scene.layout.FlowPane(8,8,ip,lookup,refresh),feedback,reputationRows);
        Tab locations=new Tab("GeoIP · ELK",geo),reputation=new Tab("IP intelligence",intelligence);locations.setClosable(false);reputation.setClosable(false);setContent(new TabPane(locations,reputation));
        LocalDateTime to=LocalDateTime.now(ZoneOffset.UTC);api.geoSummary(to.minusHours(24),to).whenComplete((data,error)->Platform.runLater(()->{
            if(!"geo-intelligence".equals(currentView)||signingOut)return;
            if(error!=null){geo.getChildren().setAll(stateLabel(message(error),"error-text"));return;}
            if(!"AVAILABLE".equals(data.sourceStatus())){geo.getChildren().setAll(stateLabel("ELK source: "+data.sourceStatus(),"error-text"));return;}
            if(data.events()==0){geo.getChildren().setAll(stateLabel("Elasticsearch available; no access log in the last 24 hours.","muted"));return;}
            geo.getChildren().setAll(stateLabel(data.events()+" logs · "+data.geolocated()+" geolocated · "+data.publicWithoutGeo()+" public-IP logs without GeoIP data\nIP scopes: "+data.scopes(),"detail-meta"));
            if(data.publicWithoutGeo()>0)geo.getChildren().add(stateLabel("Some public IPs have no GeoIP result; check City/ASN database health or address coverage.","stale-banner"));
            if(!data.locations().isEmpty()){Node table=geoTable(data.locations());geo.getChildren().add(table);VBox.setVgrow(table,Priority.ALWAYS);}
            else geo.getChildren().add(stateLabel("No location available. Private / loopback / TEST-NET addresses retain their scope labels.","muted"));
        }));
    }


    @FXML private void showGeo() {
        currentView = "geo";
        pageTitle.setText("GeoIP activity");
        cancelDashboardRequests();
        setContent(stateLabel("Đang tổng hợp vị trí nguồn truy cập…", "muted"));
        LocalDateTime to = LocalDateTime.now(ZoneOffset.UTC);
        api.geo(to.minusHours(24), to).whenComplete((items, failure) -> Platform.runLater(() -> {
            if (!"geo".equals(currentView)) return;
            if (failure != null) showError(failure); else {
                setContent(geoTable(items));
                markRefreshed();
            }
        }));
    }

    @FXML private void showHistory() {
        currentView = "history";
        pageTitle.setText("Analyst history");
        cancelDashboardRequests();
        setContent(stateLabel("Đang tải audit history…", "muted"));
        api.history().whenComplete((page, failure) -> Platform.runLater(() -> {
            if (!"history".equals(currentView)) return;
            if (failure != null) showError(failure); else {
                setContent(historyTable(page.content()));
                markRefreshed();
            }
        }));
    }

    private VBox authCorrelationPanel() {
        long generation=settingsGeneration;VBox box=new VBox(8,stateLabel("Điều tra đăng nhập và phiên", "section-title"));
        Label state=stateLabel("Đang tải policy…","muted");box.getChildren().add(state);
        api.authCorrelationPolicy().whenComplete((policy,error)->Platform.runLater(()->{
            if(!settingsCurrent(generation))return;
            if(error!=null){state.setText(message(error));return;}
            state.setText(policy.definitionVersion()+" · "+policy.mode()+" · v"+policy.version()+"\nALERT tạo ca điều tra, không tự chặn IP hoặc cô lập.");
            api.authCorrelationHistory().whenComplete((entries,historyError)->Platform.runLater(()->{
                if(!settingsCurrent(generation)||historyError!=null)return;
                VBox audit=new VBox(6,stateLabel("Lịch sử policy · workflow SOC", "muted"));
                entries.stream().limit(5).forEach(entry->audit.getChildren().add(stateLabel(entry.get("created_at")+" · "+entry.get("actor_user_id")+" · "+entry.get("mode")+" · v"+entry.get("resulting_version")+"\n"+entry.get("reason"),"note-card")));
                box.getChildren().add(audit);
            }));
            if(!isAdminUser())return;
            ComboBox<String> mode=filterBox("OFF","OBSERVE","ALERT");mode.setValue(policy.mode());
            TextField reason=new TextField();reason.setPromptText("Lý do thay đổi policy — ít nhất 10 ký tự");
            Button apply=secondaryButton("Lưu mode",()->{
                String explanation=reason.getText().trim();if(explanation.length()<10){state.setText("Lý do phải có ít nhất10 ký tự.");return;}
                String key="auth-policy:"+policy.version()+":"+mode.getValue()+":"+explanation;
                String request=pendingRevocationIds.computeIfAbsent(key,k->UUID.randomUUID().toString());
                api.changeAuthCorrelationPolicy(policy,mode.getValue(),explanation,request).whenComplete((updated,failure)->Platform.runLater(()->{
                    if(!settingsCurrent(generation))return;
                    if(failure!=null)state.setText(message(failure));else{pendingRevocationIds.remove(key);showSettings();}
                }));
            });box.getChildren().addAll(new javafx.scene.layout.FlowPane(8,8,mode,apply),reason);
        }));return box;
    }

    @FXML private void showSettings() {
        currentView = "settings";
        pageTitle.setText("SIEM settings");
        cancelDashboardRequests();
        long generation = settingsGeneration;
        VBox panel = new VBox(14, stateLabel("Đang kiểm tra backend và test windows…", "muted"));
        panel.getStyleClass().add("panel");
        setContent(panel);
        CompletableFuture<SiemModels.Page<SiemModels.UebaTrainingJob>> jobPage = isAdminUser()
                ? api.uebaTrainingJobs(trainingPage, 20)
                : CompletableFuture.completedFuture(new SiemModels.Page<>(List.of(), 0, 20, 0, 0, false));
        CompletableFuture<SiemModels.Page<SiemModels.UebaShadowRun>> shadows = isAdminUser()
                ? api.uebaShadowRuns(shadowPage, 20)
                : CompletableFuture.completedFuture(new SiemModels.Page<>(List.of(), 0, 20, 0, 0, false));
        CompletableFuture<List<SiemModels.UebaRecipe>> recipes = isAdminUser() ? api.uebaRecipes()
                : CompletableFuture.completedFuture(List.of());
        settingsRequest = api.status().thenCombine(api.testWindows(), SettingsBase::new)
                .thenCombine(api.uebaStatus(), (base, ueba) ->
                        new SettingsData(base.status(), base.windows(), ueba, null, List.of(), null))
                .thenCombine(jobPage, (data, jobs) ->
                        new SettingsData(data.status(), data.windows(), data.ueba(), jobs, List.of(), null))
                .thenCombine(recipes, (data, values) -> new SettingsData(data.status(), data.windows(), data.ueba(), data.jobs(), values, null))
                .thenCombine(shadows, (data, values) -> new SettingsData(data.status(), data.windows(), data.ueba(), data.jobs(), data.recipes(), values))
                .whenComplete((data, failure) -> Platform.runLater(() -> {
                    if (!settingsCurrent(generation)) return;
                    if (failure != null) showError(failure); else {
                        ScrollPane scroll = new ScrollPane(new VBox(14,authCorrelationPanel(),settingsPanel(data)));
                        scroll.setFitToWidth(true);
                        scroll.getStyleClass().add("overview-scroll");
                        setContent(scroll);
                        markRefreshed();
                    }
                }));
    }

    @FXML private void manualRefresh() {
        refreshHeaderHealth();
        if ("postlogin-decisions".equals(currentView)) { showPostloginDecisions();return; }
        if ("settings".equals(currentView)) showSettings();
        else if ("signatures".equals(currentView)) showSignatures();
        else if ("ip-blocks".equals(currentView)) showIpBlocks();
        else refreshCurrentView();
    }

    @FXML private void logout() {
        if (signingOut) return;
        signingOut = true;currentView="signed-out";
        ++headerGeneration;if(headerRequest!=null)headerRequest.cancel(true);
        closeIncidentWindow();
        if(incidentTable!=null)incidentTable.getItems().clear();
        contentHost.getChildren().clear();userLabel.setText("");pendingRevocationIds.clear();signedInUser=null;
        if (searchEvidence!=null)searchEvidence.dispose();
        if (refreshExecutor != null) refreshExecutor.shutdownNow();
        cancelDashboardRequests();
        api.logout().whenComplete((ignored, failure) -> Platform.runLater(() -> {
            try {
                FlareSecurityApp.showLogin();
            } catch (Exception exception) {
                throw new IllegalStateException(exception);
            }
            if (failure != null) {
                Alert warning = new Alert(Alert.AlertType.WARNING);
                warning.setTitle("Server logout not confirmed");
                warning.setHeaderText("Local session cleared");
                warning.setContentText("The server did not confirm session revocation. "
                        + "Please check the connection before signing in again.");
                warning.show();
            }
        }));
    }

    public void dispose() {
        signingOut=true;currentView="signed-out";
        ++headerGeneration;if(headerRequest!=null)headerRequest.cancel(true);
        if(contentHost!=null)contentHost.getChildren().clear();
        if(incidentTable!=null)incidentTable.getItems().clear();
        if(refreshExecutor!=null)refreshExecutor.shutdownNow();
        cancelDashboardRequests();closeIncidentWindow();
        if(searchEvidence!=null)searchEvidence.dispose();
        if(api!=null)api.clearSession();
        signedInUser=null;pendingRevocationIds.clear();queueSummaries.clear();
    }
    private void closeIncidentWindow() {
        ++detailGeneration;
        if(detailEvidence!=null)detailEvidence.dispose();
        if(detailTimeline!=null)detailTimeline.dispose();
        detailTimeline=null;detailEvidence=null;
        if(incidentStage!=null){incidentStage.setOnCloseRequest(null);incidentStage.close();incidentStage.setScene(null);}
        incidentStage=null;incidentDetail=null;openIncidentId=null;draftNote=null;draftError=null;
    }

    private void refreshHeaderHealth() {
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

    private void refreshCurrentView() {
        if(signingOut)return;
        refreshHeaderHealth();
        switch (currentView) {
            case "overview" -> refreshOverview();
            case "alerts" -> refreshIncidents();
            case "watchlist" -> refreshWatchlist();
            case "logs" -> { }
            case "geo" -> showGeo();
            case "history" -> showHistory();
            // These views have user-entered form state and an explicit refresh action.
            case "signatures", "ip-intelligence", "ip-blocks" -> { }
            // Do not discard an Admin's in-progress model/test-window form.
            // Settings has explicit refresh controls and the top-bar refresh.
            case "settings" -> { }
            default -> { }
        }
    }

    private void refreshOverview() {
        if (overviewPane == null || !"overview".equals(currentView)) return;
        if (overviewRequest != null && !overviewRequest.isDone()) overviewRequest.cancel(true);
        long generation = ++overviewGeneration;
        LocalDateTime to = LocalDateTime.now(ZoneOffset.UTC);
        LocalDateTime from = to.minusHours(overviewPane.selectedHours());
        overviewPane.setLoading(true);
        SiemModels.IncidentQuery priorityQuery = new SiemModels.IncidentQuery(
                0, 10, null, null, null, null, "OPEN", "PRIORITY", null, null);
        overviewRequest = api.dashboardSummary(from, to)
                .thenCombine(api.incidents(priorityQuery), SummaryAndPriority::new)
                .thenCombine(api.status(), OverviewBase::new)
                .thenCombine(api.preventionStatus(), (data, protection) ->
                        new OverviewData(data.summaryAndPriority(), data.status(), protection))
                .whenComplete((data, failure) -> Platform.runLater(() -> {
                    if (generation != overviewGeneration || !"overview".equals(currentView)) return;
                    overviewPane.setLoading(false);
                    if (failure != null) {
                        overviewPane.showRefreshError(message(failure));
                        connectionLabel.setText("DEGRADED");
                        connectionLabel.getStyleClass().setAll("status-pill", "status-error");
                        return;
                    }
                    overviewFrom = from;
                    overviewTo = to;
                    overviewPane.update(data.summaryAndPriority.summary(),
                            data.summaryAndPriority.priority().content(), data.prevention());
                    api.queueSummaries(data.summaryAndPriority.priority().content().stream().map(SiemModels.Incident::id).toList()).whenComplete((page,error)->Platform.runLater(()->{
                        if(generation!=overviewGeneration||!"overview".equals(currentView)||signingOut)return;
                        if(error==null)overviewPane.updateEvidence(page.content());
                    }));
                    api.investigationMetrics(from,to).whenComplete((metrics,error)->Platform.runLater(()->{
                        if(generation!=overviewGeneration||!"overview".equals(currentView)||signingOut)return;
                        if(error==null)overviewPane.updateMetrics(metrics);
                    }));
                    connectionLabel.setText(data.status.elasticsearchAvailable() ? "ELASTIC ONLINE" : "ELASTIC OFFLINE");
                    connectionLabel.getStyleClass().setAll("status-pill",
                            data.status.elasticsearchAvailable() ? "status-ok" : "status-error");
                    markRefreshed();
                }));
    }

    private void openChartFilter(OverviewPane.ChartFilter filter) {
        String status = "status".equals(filter.dimension()) ? filter.value() : null;
        String severity = "severity".equals(filter.dimension()) ? filter.value() : null;
        String classification = "classification".equals(filter.dimension()) ? filter.value() : null;
        openIncidentQueue(status, severity, classification, overviewFrom, overviewTo);
        configuringFilters = true;
        selectFilter(queueTierFilter, "queueTier".equals(filter.dimension()) ? filter.value() : null);
        selectFilter(originFilter, "origin".equals(filter.dimension()) ? filter.value() : null);
        configuringFilters = false;
        resetPageAndRefresh();
    }

    private void openPriorityIncident(SiemModels.Incident incident) {
        pendingIncidentId = incident.id();
        openIncidentQueue(null, null, null, null, null);
        openIncident(incident.id());
    }

    private void openIncidentQueue(
            String status,
            String severity,
            String classification,
            LocalDateTime from,
            LocalDateTime to
    ) {
        currentView = "alerts";
        pageTitle.setText("Incident queue");
        cancelOverviewRequest();
        buildIncidentQueue();
        configuringFilters = true;
        incidentFrom = from;
        incidentTo = to;
        incidentScope = from == null ? "OPEN" : "ALL";
        selectFilter(statusFilter, status == null ? (from == null ? "OPEN" : "ALL") : status);
        selectFilter(severityFilter, severity);
        selectFilter(classificationFilter, classification);
        selectFilter(sortFilter, from == null ? "PRIORITY" : "LATEST");
        selectFilter(queueTierFilter, defaultQueueTier());
        selectFilter(originFilter, null);
        mineFilter.setSelected(false);
        configuringFilters = false;
        refreshIncidents();
    }

    private void buildIncidentQueue() {
        incidentPage = 0;
        incidentTotalPages = 0;
        incidentFrom = null;
        incidentTo = null;
        incidentScope = "OPEN";
        incidentSearch = new TextField();
        incidentSearch.setPromptText("Search IP, rule or incident title");
        incidentSearch.setOnAction(event -> resetPageAndRefresh());
        severityFilter = filterBox(
                new FilterOption("All severities", null), new FilterOption("Urgent", "URGENT"),
                new FilterOption("High", "HIGH"), new FilterOption("Medium", "MEDIUM"),
                new FilterOption("Low", "LOW"));
        statusFilter = filterBox(
                new FilterOption("All open", "OPEN"), new FilterOption("New", "NEW"),
                new FilterOption("In progress", "IN_PROGRESS"), new FilterOption("Closed", "CLOSED"),
                new FilterOption("All statuses", "ALL"));
        classificationFilter = filterBox(
                new FilterOption("All classifications", null),
                new FilterOption("Investigate", "INVESTIGATE"),
                new FilterOption("Potential noise", "POTENTIAL_NOISE"));
        sortFilter = filterBox(new FilterOption("Priority", "PRIORITY"), new FilterOption("Latest", "LATEST"));
        queueTierFilter = filterBox(new FilterOption("My tier", defaultQueueTier()),
                new FilterOption("SOC L1", "L1"), new FilterOption("SOC L2", "L2"),
                new FilterOption("Both tiers", null));
        originFilter = filterBox(new FilterOption("All sources", null),
                new FilterOption("ELK rules", "ELASTIC"), new FilterOption("Account behavior", "UEBA"),
                new FilterOption("Gateway protection", "PREVENTION"),new FilterOption("Correlation", "CORRELATION"),new FilterOption("Manual", "MANUAL"),new FilterOption("Unknown", "UNKNOWN"));
        mineFilter = new CheckBox("Assigned to me");
        severityFilter.setOnAction(event -> { if (!configuringFilters) resetPageAndRefresh(); });
        statusFilter.setOnAction(event -> {
            if (!configuringFilters) { updateScopeFromStatus(); resetPageAndRefresh(); }
        });
        classificationFilter.setOnAction(event -> { if (!configuringFilters) resetPageAndRefresh(); });
        sortFilter.setOnAction(event -> { if (!configuringFilters) resetPageAndRefresh(); });
        queueTierFilter.setOnAction(event -> { if (!configuringFilters) resetPageAndRefresh(); });
        originFilter.setOnAction(event -> { if (!configuringFilters) resetPageAndRefresh(); });
        mineFilter.setOnAction(event -> { if (!configuringFilters) resetPageAndRefresh(); });

        Button searchButton = secondaryButton("Search", this::resetPageAndRefresh);
        Button clearButton = secondaryButton("Clear filters", this::clearIncidentFilters);
        HBox searchRow = new HBox(8, incidentSearch, searchButton, clearButton);
        HBox.setHgrow(incidentSearch, Priority.ALWAYS);
        javafx.scene.layout.FlowPane filters=new javafx.scene.layout.FlowPane(8,8,new Label("Mức độ"),severityFilter,new Label("Trạng thái"),statusFilter,new Label("Tier"),queueTierFilter,mineFilter);
        javafx.scene.layout.FlowPane ownershipFilters=new javafx.scene.layout.FlowPane(8,8);
        javafx.scene.layout.FlowPane advanced=new javafx.scene.layout.FlowPane(8,8,new Label("Phân loại"),classificationFilter,new Label("Sắp xếp"),sortFilter,new Label("Nguồn"),originFilter);
        advanced.setVisible(false);advanced.setManaged(false);
        Button more=secondaryButton("Bộ lọc thêm",()->{boolean show=!advanced.isManaged();advanced.setManaged(show);advanced.setVisible(show);});filters.getChildren().add(more);
        incidentError = stateLabel("", "stale-banner");
        incidentError.setVisible(false);
        incidentError.setManaged(false);

        incidentTable = incidentTable();
        Button open=secondaryButton("Mở xử lý",()->{
            var selected=incidentTable.getSelectionModel().getSelectedItem();if(selected!=null)openIncident(selected.id());
        });
        Button discover=secondaryButton("ELK Discover",this::showLogs);
        Button accounts=secondaryButton("Account watchlist",this::showWatchlist);
        ownershipFilters.getChildren().addAll(open,discover,accounts);

        previousPage = secondaryButton("← Previous", () -> { if (incidentPage > 0) { incidentPage--; refreshIncidents(); } });
        nextPage = secondaryButton("Next →", () -> {
            if (incidentPage + 1 < incidentTotalPages) { incidentPage++; refreshIncidents(); }
        });
        pageLabel = new Label("Page 1");
        pageLabel.getStyleClass().add("muted");
        HBox pagination = new HBox(9, previousPage, pageLabel, nextPage);
        pagination.setAlignment(Pos.CENTER_RIGHT);

        VBox root = new VBox(10, searchRow, filters, advanced, ownershipFilters, incidentError, incidentTable, pagination);
        VBox.setVgrow(incidentTable, Priority.ALWAYS);
        setContent(root);
    }

    private void refreshIncidents() {
        if (incidentTable == null || !"alerts".equals(currentView)) return;
        if (incidentRequest != null && !incidentRequest.isDone()) incidentRequest.cancel(true);
        long generation = ++incidentGeneration;
        String statusValue = filterValue(statusFilter);
        String apiStatus = "OPEN".equals(statusValue) || "ALL".equals(statusValue) ? null : statusValue;
        SiemModels.IncidentQuery query = new SiemModels.IncidentQuery(
                incidentPage, 50, incidentSearch.getText(), apiStatus, filterValue(severityFilter),
                filterValue(classificationFilter), incidentScope, filterValue(sortFilter), incidentFrom, incidentTo,
                filterValue(queueTierFilter), filterValue(originFilter), null, mineFilter.isSelected());
        incidentRequest = api.incidents(query).whenComplete((page, failure) -> Platform.runLater(() -> {
            if (generation != incidentGeneration || !"alerts".equals(currentView)) return;
            if (failure != null) {
                incidentError.setText("Showing last successful data · " + message(failure));
                incidentError.setVisible(true);
                incidentError.setManaged(true);
                return;
            }
            incidentError.setVisible(false);
            incidentError.setManaged(false);
            var selectedBefore=incidentTable.getSelectionModel().getSelectedItem();
            String selectedId=selectedBefore==null?null:selectedBefore.id();
            queueSummaries.clear();
            incidentTable.getItems().setAll(page.content());
            if(!page.content().isEmpty())api.queueSummaries(page.content().stream().map(SiemModels.Incident::id).toList()).whenComplete((enriched,error)->Platform.runLater(()->{
                if(signingOut||generation!=incidentGeneration||!"alerts".equals(currentView))return;
                if(error==null){enriched.content().forEach(item->queueSummaries.put(item.incident().id(),item));incidentTable.refresh();}
            }));
            if(pendingIncidentId==null && selectedId!=null)page.content().stream().filter(item->selectedId.equals(item.id())).findFirst().ifPresent(item->incidentTable.getSelectionModel().select(item));
            incidentTotalPages = page.totalPages();
            pageLabel.setText("Page " + (page.page() + 1) + " of " + Math.max(1, page.totalPages())
                    + " · " + page.totalElements() + " incidents");
            previousPage.setDisable(page.page() == 0);
            nextPage.setDisable(!page.hasNext());
            if (pendingIncidentId != null) {
                page.content().stream().filter(item -> item.id().equals(pendingIncidentId)).findFirst()
                        .ifPresent(item -> {
                            incidentTable.getSelectionModel().select(item);
                            incidentTable.scrollTo(item);
                        });
                pendingIncidentId = null;
            }
            markRefreshed();
        }));
    }

    private void updateScopeFromStatus() {
        String value = filterValue(statusFilter);
        if ("OPEN".equals(value)) {
            incidentScope = "OPEN";
        } else if ("CLOSED".equals(value) || "ALL".equals(value)) {
            incidentScope = "ALL";
        } else {
            incidentScope = incidentFrom != null ? "ALL" : "OPEN";
        }
    }

    private void clearIncidentFilters() {
        configuringFilters = true;
        incidentSearch.clear();
        selectFilter(severityFilter, null);
        selectFilter(statusFilter, "OPEN");
        selectFilter(classificationFilter, null);
        selectFilter(sortFilter, "PRIORITY");
        selectFilter(queueTierFilter, defaultQueueTier());
        selectFilter(originFilter, null);
        mineFilter.setSelected(false);
        incidentScope = "OPEN";
        incidentFrom = null;
        incidentTo = null;
        incidentPage = 0;
        configuringFilters = false;
        refreshIncidents();
    }

    private void resetPageAndRefresh() { incidentPage = 0; refreshIncidents(); }

    private String defaultQueueTier() {
        String role=SiemModels.socRole(signedInUser);
        return "L1".equals(role)||"L2".equals(role)?role:null;
    }

    private TableView<SiemModels.Incident> incidentTable() {
        TableView<SiemModels.Incident> table = new TableView<>();
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.getColumns().add(column("Mức độ",85,SiemModels.Incident::severity));
        table.getColumns().add(column("Tình huống",270,item->{var view=queueSummaries.get(item.id());return view==null?IncidentPresentation.scenario(item):IncidentPresentation.scenario(item,view.observed(),view.sourceStatus());}));
        table.getColumns().add(column("Nguồn",140,item->queueValue(item,"source.ip",item.sourceIp()==null?"Không ghi nhận":item.sourceIp())));
        table.getColumns().add(column("Đích / server",160,item->{String destination=queueValue(item,"destination.ip",null);return destination!=null?destination:queueValue(item,"server.ip","Không ghi nhận").equals("Không ghi nhận")?"Không ghi nhận":"server "+queueValue(item,"server.ip","");}));
        table.getColumns().add(column("Tài khoản",140,item->queueValue(item,"user.name",item.targetUserId())));
        table.getColumns().add(column("Trạng thái",115,item->switch(item.status()){case "NEW"->"Mới";case "IN_PROGRESS"->"Đang xử lý";case "CLOSED"->"Đã đóng";default->item.status();}));
        table.getColumns().add(column("Người nhận",180,IncidentPresentation::assignee));
        table.getColumns().add(column("Thời gian xảy ra",150,item->{var view=queueSummaries.get(item.id());return IncidentPresentation.occurredAt(item,view!=null&&"AVAILABLE".equals(view.sourceStatus())?view.firstObservedAt():null);}));
        double[] minimumWidths={70,180,120,140,110,105,180,150};
        for(int i=0;i<minimumWidths.length;i++)table.getColumns().get(i).setMinWidth(minimumWidths[i]);
        table.setFixedCellSize(46);
        table.setRowFactory(t->{
            javafx.scene.control.TableRow<SiemModels.Incident> row=new javafx.scene.control.TableRow<>();
            row.setOnMouseClicked(event->{if(event.getClickCount()==2&&!row.isEmpty())openIncident(row.getItem().id());});return row;
        });
        table.setOnKeyPressed(event->{if(event.getCode()==KeyCode.ENTER){
            var selected=table.getSelectionModel().getSelectedItem();if(selected!=null)openIncident(selected.id());event.consume();
        }});
        return table;
    }

    private String queueValue(SiemModels.Incident incident,String field,String fallback){
        var summary=queueSummaries.get(incident.id());if(summary==null)return fallback;
        var group=summary.observed().get(field);if(group==null||group.values().isEmpty())return fallback;
        return group.values().stream().map(SiemModels.ObservedValue::value).collect(java.util.stream.Collectors.joining(", "))+(group.hasMore()?" …":"");
    }

    private void openIncident(String id) {
        if(signingOut)return;
        if(id.equals(openIncidentId) && incidentStage!=null){incidentStage.show();incidentStage.toFront();return;}
        confirmDraft(()->{
            if(detailEvidence!=null)detailEvidence.dispose();
            if(detailTimeline!=null)detailTimeline.dispose();
            openIncidentId=id;draftNote=null;draftError=null;
            if(incidentStage==null){
                incidentStage=new Stage();incidentStage.initOwner(contentHost.getScene().getWindow());
                incidentStage.setResizable(true);
                incidentDetail=new VBox(12);incidentDetail.getStyleClass().add("detail-panel");
                incidentDetail.setMinHeight(0);incidentDetail.setFillWidth(true);
                Scene scene=new Scene(incidentDetail);scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());
                incidentStage.setScene(scene);
                var screens=javafx.stage.Screen.getScreensForRectangle(contentHost.getScene().getWindow().getX(),contentHost.getScene().getWindow().getY(),1,1);
                var bounds=(screens.isEmpty()?javafx.stage.Screen.getPrimary():screens.getFirst()).getVisualBounds();
                incidentStage.setWidth(Math.min(1280,bounds.getWidth()-48));incidentStage.setHeight(Math.min(820,bounds.getHeight()-48));
                incidentStage.setMinWidth(Math.min(760,bounds.getWidth()-48));incidentStage.setMinHeight(Math.min(540,bounds.getHeight()-48));
                incidentStage.setX(bounds.getMinX()+(bounds.getWidth()-incidentStage.getWidth())/2);
                incidentStage.setY(bounds.getMinY()+(bounds.getHeight()-incidentStage.getHeight())/2);
                incidentStage.setOnCloseRequest(event->{event.consume();confirmDraft(this::closeIncidentWindow);});
                scene.addEventHandler(javafx.scene.input.KeyEvent.KEY_PRESSED,event->{
                    if(event.getCode()==KeyCode.F11){incidentStage.setFullScreen(!incidentStage.isFullScreen());event.consume();}
                });
            }
            incidentDetail.getChildren().setAll(stateLabel("Đang tải tình huống…","muted"));
            incidentStage.setTitle("Incident · "+id);incidentStage.show();incidentStage.toFront();loadIncidentDetail(id);
        });
    }
    private void confirmDraft(Runnable next) {
        if(noteSaving)return;
        if(draftNote==null || draftNote.getText().isBlank()){next.run();return;}
        ButtonType save=new ButtonType("Lưu"),discard=new ButtonType("Bỏ thay đổi"),cancel=new ButtonType("Hủy",javafx.scene.control.ButtonBar.ButtonData.CANCEL_CLOSE);
        Alert dialog=new Alert(Alert.AlertType.CONFIRMATION,"Ghi chú chưa lưu của "+openIncidentId,save,discard,cancel);
        if(incidentStage!=null)dialog.initOwner(incidentStage);
        dialog.setHeaderText("Lưu ghi chú trước khi chuyển hoặc đóng ca?");
        ButtonType choice=dialog.showAndWait().orElse(cancel);
        if(choice==discard){draftNote.clear();next.run();}else if(choice==save)saveDraft(next);
    }
    private void saveDraft(Runnable next) {
        if(noteSaving || draftNote==null || draftNote.getText().isBlank())return;
        String id=openIncidentId;TextArea note=draftNote;Label error=draftError;
        String content=note.getText();noteSaving=true;note.setDisable(true);error.setText("Saving note…");
        api.addNote(id,content).whenComplete((saved,failure)->Platform.runLater(()->{
            noteSaving=false;if(signingOut || !Objects.equals(openIncidentId,id))return;
            note.setDisable(false);
            if(failure!=null){error.setText(message(failure));return;}
            note.clear();error.setText("Saved");next.run();
        }));
    }
    private void loadIncidentDetail(String id) {
        if(signingOut || incidentDetail==null || !Objects.equals(openIncidentId,id))return;
        long generation=++detailGeneration;
        var future=api.incident(id).thenCompose(detail->{
            var history="CLOSED".equals(detail.incident().status())?api.incidentHistory(id):CompletableFuture.<List<SiemModels.History>>completedFuture(List.of());
            return history.thenApply(items->new IncidentBundle(detail,List.of(),List.of(),items,List.of(),List.of(),0,List.of()));
        })
            .thenCompose(bundle->{
                if(!"UEBA".equals(bundle.detail.incident().origin()))return CompletableFuture.completedFuture(bundle);
                return api.incidentBehaviorWindows(id).thenCombine(api.incidentSecurityEvents(id),(windows,events)->
                    new IncidentBundle(bundle.detail,bundle.alerts,bundle.logs,bundle.history,windows.content(),events.content(),events.totalElements(),List.of()));
            }).thenCombine(api.incidentIpIntelligence(id).exceptionally(ignored->List.of()),(bundle,intel)->
                new IncidentBundle(bundle.detail,bundle.alerts,bundle.logs,bundle.history,bundle.behaviorWindows,bundle.securityEvents,bundle.totalSecurityEvents,intel));
        future.whenComplete((bundle,failure)->Platform.runLater(()->{
            if(signingOut || generation!=detailGeneration || !Objects.equals(openIncidentId,id) || incidentDetail==null)return;
            if(failure!=null){
                if(incidentDetail.getChildren().isEmpty())incidentDetail.getChildren().add(stateLabel(message(failure),"error-text"));
                else if(draftError!=null)draftError.setText(message(failure));
                return;
            }
            String draft=draftNote==null?"":draftNote.getText();
            String selectedTab=incidentDetail.lookup("#incident-tabs") instanceof TabPane tabs&&tabs.getSelectionModel().getSelectedItem()!=null?tabs.getSelectionModel().getSelectedItem().getId():null;
            if(detailEvidence!=null)detailEvidence.dispose();
            if(detailTimeline!=null)detailTimeline.dispose();
            incidentDetail.getChildren().setAll(incidentDetailNodes(bundle));draftNote.setText(draft);
            if(selectedTab!=null&&incidentDetail.lookup("#incident-tabs") instanceof TabPane tabs)
                tabs.getTabs().stream().filter(tab->selectedTab.equals(tab.getId())).findFirst().ifPresent(tab->tabs.getSelectionModel().select(tab));
        }));
    }
    private TitledPane section(String title,Node body,boolean expanded) {
        TitledPane pane=new TitledPane();pane.setContent(body);pane.setExpanded(expanded);pane.setAnimated(false);
        pane.textProperty().bind(javafx.beans.binding.Bindings.when(pane.expandedProperty()).then("▲  "+title).otherwise("▼  "+title));
        return pane;
    }
    private List<Node> incidentDetailNodes(IncidentBundle bundle) {
        SiemModels.Incident incident=bundle.detail.incident();
        Label title=stateLabel(IncidentPresentation.scenario(incident),"detail-title");
        Label identity=stateLabel("","detail-meta");
        Label network=stateLabel("Nguồn workflow: "+safe(incident.sourceIp())+"\nĐích / server: chưa có dữ liệu quan sát","detail-meta");
        Label accounts=stateLabel("Tài khoản liên quan (workflow): "+safe(incident.targetUserId())+"\nNgười thực hiện: Chưa có trong log","detail-meta");
        Label signal=stateLabel("","reason-box");
        Label response=stateLabel(IncidentPresentation.assignee(incident),"detail-meta");
        boolean fixture=incident.classificationReason()!=null&&incident.classificationReason().contains("DEMO_ONLY_WORKFLOW_FIXTURE");
        String provenance=fixture?"WORKFLOW FIXTURE":"UEBA".equals(incident.origin())?"MODEL / PROJECT_LIMITED":safe(incident.origin());
        identity.setText(incident.severity()+" · "+incident.status()+" · "+provenance+"\nThời gian xảy ra: "+IncidentPresentation.occurredAt(incident)+" (VN) · "+incident.id());
        identity.setTooltip(new javafx.scene.control.Tooltip("UTC "+safeTime(incident.firstSeen())+" → "+safeTime(incident.lastSeen())));
        signal.setText("Rule: "+safe(incident.ruleId())+(fixture?"\nCa thực hành; không có log phát hiện live.":""));
        signal.setTooltip(new javafx.scene.control.Tooltip(safe(incident.classificationReason())));
        Label evidenceState=stateLabel("Đang đối chiếu bằng chứng…","muted");
        HBox facts=new HBox(16,network,accounts,signal);facts.getChildren().forEach(n->{HBox.setHgrow(n,Priority.ALWAYS);((javafx.scene.layout.Region)n).setPrefWidth(380);});
        VBox summary=new VBox(8,title,identity,facts,evidenceState);summary.getStyleClass().add("investigation-header");
        for(Label label:List.of(title,identity,network,accounts,signal,evidenceState)){label.setMinHeight(javafx.scene.layout.Region.USE_PREF_SIZE);label.setMaxWidth(Double.MAX_VALUE);}
        summary.setMinHeight(javafx.scene.layout.Region.USE_PREF_SIZE);facts.setMinHeight(javafx.scene.layout.Region.USE_PREF_SIZE);
        detailTimeline=new InvestigationTimelinePane(api,incident.id());
        long summaryGeneration=detailGeneration;
        api.investigationSummary(incident.id()).whenComplete((view,error)->Platform.runLater(()->{
            if(signingOut||summaryGeneration!=detailGeneration||!Objects.equals(openIncidentId,incident.id()))return;
            if(error!=null){evidenceState.setText("Chưa tải được ELK summary; giữ thông tin workflow.");return;}
            title.setText(IncidentPresentation.scenario(incident,view.observed(),view.sourceStatus()));
            var observedAt="AVAILABLE".equals(view.sourceStatus())?view.firstObservedAt():null;
            identity.setText(incident.severity()+" · "+incident.status()+" · "+provenance+"\nThời gian xảy ra: "+IncidentPresentation.occurredAt(incident,observedAt)+" (VN) · "+incident.id());
            identity.setTooltip(new javafx.scene.control.Tooltip("Mốc ca: "+localBusinessTime(incident.firstSeen())+" (VN). Thời gian log: log trực tiếp sớm nhất còn lưu trong phạm vi bằng chứng; mốc ca ELK/model có thể là lúc phát hiện hoặc đầu cửa sổ."));
            String observedSource=observedValues(view,"source.ip");
            boolean sourceMissing="Không ghi nhận".equals(observedSource);
            String workflowSource=incident.sourceIp();String sourceText=sourceMissing?"IP nguồn (workflow): "+safe(workflowSource):"IP nguồn (ELK): "+observedSource;
            if(!sourceMissing&&workflowSource!=null&&!observedSource.equals(workflowSource))sourceText+="\nWorkflow: "+workflowSource;
            network.setText(sourceText+"\nĐích: "+observedValues(view,"destination.ip")+" · port "+observedValues(view,"destination.port")
                +"\nServer quan sát: "+observedValues(view,"server.ip")+" · port "+observedValues(view,"server.port"));
            String target=observedValues(view,"target.user.id"),actorId=observedValues(view,"user.id"),session=observedValues(view,"session.pseudonym");
            String accountText="Người thực hiện: "+observedValues(view,"user.name")+" ["+actorId+"]\nTài khoản bị tác động: "+target;
            if(incident.targetUserId()!=null&&!incident.targetUserId().equals(target))accountText+="\nWorkflow: "+incident.targetUserId();
            accounts.setText(accountText+"\nSession: "+(session.length()>20?session.substring(0,16)+"…":session));
            signal.setText("Rule: "+safe(incident.ruleId())+"\nAction: "+observedValues(view,"event.action")
                +" · "+observedValues(view,"event.outcome")+"\nHTTP: "+observedValues(view,"http.response.status_code")
);
            String clues=java.util.stream.Stream.of("event.reason","error.message","message").filter(key->view.observed().containsKey(key)&&!view.observed().get(key).values().isEmpty()).map(key->observedValues(view,key)).collect(java.util.stream.Collectors.joining(" · "));
            if(!clues.isBlank())signal.setText(signal.getText()+"\n"+clues);
            if("NO_DETECTION_LOG".equals(view.sourceStatus())||"UNAVAILABLE".equals(view.sourceStatus())||"DISABLED".equals(view.sourceStatus())){
                network.setText("IP nguồn (workflow): "+safe(incident.sourceIp())+"\nĐích / server: chưa có bằng chứng quan sát");
                accounts.setText("Tài khoản liên quan (workflow): "+safe(incident.targetUserId())+"\nPrincipal / session: chưa có bằng chứng quan sát");
                signal.setText("Rule: "+safe(incident.ruleId()));
            }
            network.setTooltip(new javafx.scene.control.Tooltip(observedDetails(view)));accounts.setTooltip(new javafx.scene.control.Tooltip(observedDetails(view)));
            evidenceState.setText(switch(view.sourceStatus()){case "NO_DETECTION_LOG"->"Không có log phát hiện — thông tin workflow được giữ riêng.";case "AVAILABLE"->"Bằng chứng ELK trực tiếp · summary toàn phạm vi ca";default->"Trạng thái bằng chứng: "+view.sourceStatus();});
        }));
        Label context=stateLabel(BehaviorSignalSummary.describe(bundle.behaviorWindows,bundle.securityEvents)+"\n"+BehaviorSignalSummary.CAUTION
                +"\nBased on loaded retained evidence; missing or paginated evidence may limit context.","reason-box");
        if("UEBA".equals(incident.origin()))context.setId("ueba-signal-context");
        VBox analysis=new VBox(8);
        if("UEBA".equals(incident.origin()))analysis.getChildren().addAll(stateLabel("MySQL workflow / model context · separate from original ELK documents","muted"),context);
        for(var intel:bundle.ipIntelligence)analysis.getChildren().add(stateLabel(intel.ipAddress()+" · "+intel.provider()+" · "+intel.status()+" · "+safe(intel.dataProvenance()),"note-card"));
        for(var window:bundle.behaviorWindows)analysis.getChildren().add(section("Model snapshot · "+safeTime(window.windowStart()),stateLabel(BehaviorSignalSummary.describe(window)+"\nModel "+safe(window.modelVersion())+"\nFeatures "+window.features()+"\nSignals "+safe(window.riskReasons()),"note-card"),false));
        draftNote=new TextArea();draftNote.setPromptText("Ghi chú điều tra · tối đa 2000 ký tự");draftNote.setPrefRowCount(4);
        TextArea actionReason=new TextArea();actionReason.setPromptText("Lý do xử lý / cô lập / kiểm tra — tách khỏi ghi chú");actionReason.setPrefRowCount(3);
        draftError=stateLabel("","error-text");
        Button save=actionButton("Lưu ghi chú",()->saveDraft(()->loadIncidentDetail(incident.id())));
        ComboBox<String> conclusion=new ComboBox<>();if(isHigherTierUser())conclusion.getItems().add("TRUE_POSITIVE");conclusion.getItems().addAll("FALSE_POSITIVE","BENIGN_ACTIVITY");conclusion.setPromptText("Chọn kết luận sau điều tra");conclusion.getSelectionModel().clearSelection();
        FlowPaneActions actions=new FlowPaneActions();boolean higher=isHigherTierUser();
        boolean assigned=signedInUser!=null&&signedInUser.id().equals(incident.assigneeUserId());
        if("NEW".equals(incident.status()))actions.add(actionButton("Claim",()->transition(incident,"CLAIM",null,null,draftError)));
        if(assigned&&"IN_PROGRESS".equals(incident.status())){
            if("L1".equals(incident.queueTier()))actions.add(actionButton("Escalate to L2",()->transition(incident,"ESCALATE",actionReason.getText(),null,draftError)));
            if(higher&&"L2".equals(incident.queueTier())){
                actions.add(actionButton("Return to L1",()->transition(incident,"RETURN_TO_L1",actionReason.getText(),null,draftError)));
                if("UEBA".equals(incident.origin())&&incident.targetUserId()!=null)actions.add(actionButton("Revoke customer sessions",()->confirmSessionRevocation(incident,draftError)));
            }
            if(higher||(!incident.missingData()&&List.of("LOW","MEDIUM").contains(incident.severity())))
                actions.add(actionButton("Close",()->{if(conclusion.getValue()==null){draftError.setText("Chọn kết luận trước khi đóng ca.");return;}transition(incident,"CLOSE",actionReason.getText(),conclusion.getValue(),draftError);}));
        }
        if("CLOSED".equals(incident.status()))actions.add(actionButton("Reopen",()->transition(incident,"REOPEN",actionReason.getText(),null,draftError)));
        ComboBox<String> responseCheck=filterBox("PASSED","NOT_REQUIRED"),recoveryCheck=filterBox("PASSED","NOT_REQUIRED");
        Button verify=actionButton("Ghi nhận kiểm tra response / recovery",()->{
            String reason=actionReason.getText().trim();if(reason.length()<10||reason.length()>500){draftError.setText("Lý do kiểm tra: 10–500 ký tự.");return;}
            String key="verify:"+incident.id()+":"+incident.version()+":"+reason+":"+responseCheck.getValue()+":"+recoveryCheck.getValue();
            api.verifyResponse(incident,reason,responseCheck.getValue(),recoveryCheck.getValue(),pendingRevocationIds.computeIfAbsent(key,k->UUID.randomUUID().toString()))
                .whenComplete((value,error)->Platform.runLater(()->{if(!Objects.equals(openIncidentId,incident.id())||signingOut)return;if(error!=null)draftError.setText(message(error));else{pendingRevocationIds.remove(key);loadIncidentDetail(incident.id());}}));
        });verify.setDisable(!higher);
        VBox noteInput=new VBox(8,new Label("Ghi chú điều tra"),draftNote),reasonInput=new VBox(8,new Label("Lý do thao tác"),actionReason);
        noteInput.setMinWidth(0);reasonInput.setMinWidth(0);noteInput.setPrefWidth(500);reasonInput.setPrefWidth(500);
        HBox inputs=new HBox(12,noteInput,reasonInput);HBox.setHgrow(noteInput,Priority.ALWAYS);HBox.setHgrow(reasonInput,Priority.ALWAYS);
        VBox treatment=new VBox(10,new Label("Kết luận"),conclusion,inputs);
        VBox responseOptions=new VBox(10);
        if(higher)responseOptions.getChildren().addAll(stateLabel("Kiểm tra phản ứng và phục hồi","section-title"),
                stateLabel("ACK gateway được server xác nhận; kết quả kiểm tra do analyst ghi nhận.","muted"),
                new javafx.scene.layout.FlowPane(8,8,responseCheck,recoveryCheck,verify));
        if(higher && incident.targetUserId()!=null){
            ComboBox<String> duration=filterBox("15_MINUTES","1_HOUR","24_HOURS","UNTIL_REVOKED");
            Button isolate=actionButton("Cô lập tài khoản",()->{
                String reason=actionReason.getText().trim();if(reason.length()<10){draftError.setText("Nhập lý do ít nhất 10 ký tự.");return;}
                String key=incident.id()+":"+incident.version()+":"+reason+":"+duration.getValue();
                String request=pendingRevocationIds.computeIfAbsent(key,k->UUID.randomUUID().toString());
                api.isolate(incident,reason,duration.getValue(),request).whenComplete((result,failure)->Platform.runLater(()->{
                    if(!Objects.equals(openIncidentId,incident.id())||signingOut)return;
                    if(failure!=null)draftError.setText(message(failure));else{pendingRevocationIds.remove(key);loadIncidentDetail(incident.id());}
                }));
            });responseOptions.getChildren().add(new javafx.scene.layout.FlowPane(8,8,duration,isolate));
        }
        VBox containment=new VBox(8,stateLabel("Đang tải trạng thái cô lập…","muted"));responseOptions.getChildren().add(containment);
        long actionGeneration=detailGeneration;
        api.containment(incident.id()).whenComplete((items,failure)->Platform.runLater(()->{
            if(signingOut || !Objects.equals(openIncidentId,incident.id()) || actionGeneration!=detailGeneration)return;
            containment.getChildren().clear();
            if(failure!=null){containment.getChildren().add(stateLabel(message(failure),"error-text"));return;}
            List<SiemModels.ContainmentAction> active=items.stream().filter(a->"APPLIED".equals(a.status()) && (a.expiresAt()==null || a.expiresAt().isAfter(LocalDateTime.now(ZoneOffset.UTC)))).toList();
            response.setText(IncidentPresentation.assignee(incident)+" · Hàng đợi "+incident.queueTier()+"\nCô lập tài khoản đang hiệu lực ("+active.size()+"): "+(active.isEmpty()?"Không có":active.stream().map(a->a.targetUserId()+" · "+(a.expiresAt()==null?"Đến khi gỡ":safeTime(a.expiresAt())+" UTC")).collect(java.util.stream.Collectors.joining("; "))));
            for(var action:items){
                if(!"CLOSED".equals(incident.status())&&!active.contains(action)&&!List.of("PENDING","FAILED").contains(action.status()))continue;
                Label value=stateLabel(action.status()+" · "+action.targetUserId()+" · "+(action.expiresAt()==null?"Đến khi gỡ":safeTime(action.expiresAt()))+"\n"+action.reason(),"note-card");containment.getChildren().add(value);
                if(higher&&"APPLIED".equals(action.status()))containment.getChildren().add(actionButton("Gỡ cô lập",()->{
                    TextInputDialog reason=new TextInputDialog();reason.setHeaderText("Lý do gỡ cô lập (ít nhất 10 ký tự)");
                    reason.showAndWait().filter(r->r.trim().length()>=10).ifPresent(r->{String key=action.id()+":"+action.version()+":"+r;String request=pendingRevocationIds.computeIfAbsent(key,k->UUID.randomUUID().toString());
                        api.release(action,r,request).whenComplete((result,error)->Platform.runLater(()->{if(!Objects.equals(openIncidentId,incident.id())||signingOut)return;if(error!=null)draftError.setText(message(error));else{pendingRevocationIds.remove(key);loadIncidentDetail(incident.id());}}));});
                }));
            }
        }));
        VBox savedNotes=new VBox(8);
        if(!bundle.detail.notes().isEmpty())savedNotes.getChildren().add(stateLabel("Ghi chú đã lưu","section-title"));
        bundle.detail.notes().forEach(n->savedNotes.getChildren().add(stateLabel(n.authorUserId()+" · "+localBusinessTime(n.createdAt())+"\n"+n.content(),"note-card")));
        VBox handling=new VBox(10,stateLabel("Xử lý", "section-title"),response,treatment,save,actions,draftError,responseOptions,savedNotes);
        handling.setId("incident-treatment");handling.getStyleClass().add("response-panel");
        VBox information=new VBox(16,summary);
        if("UEBA".equals(incident.origin())||!bundle.ipIntelligence.isEmpty())information.getChildren().add(section("Phân tích liên quan",analysis,false));
        information.getChildren().add(handling);
        if("CLOSED".equals(incident.status())){
            VBox history=new VBox(8,stateLabel("Quá trình xử lý đã hoàn tất","section-title"));history.setId("incident-handling-history");
            bundle.history.stream().sorted(java.util.Comparator.comparing(SiemModels.History::createdAt)).forEach(h->history.getChildren().add(stateLabel(localBusinessTime(h.createdAt())+" · "+h.action()+" · "+safe(h.actorUserId())+"\n"+safe(h.detail()),"note-card")));
            if(bundle.history.isEmpty())history.getChildren().add(stateLabel("Chưa có lịch sử xử lý được lưu.","muted"));
            information.getChildren().add(history);
        }
        ScrollPane informationScroll=new ScrollPane(information);informationScroll.setFitToWidth(true);informationScroll.setMinWidth(0);informationScroll.setId("incident-information-scroll");
        Tab details=new Tab("Thông tin log",informationScroll),timeline=new Tab("Dòng thời gian log",detailTimeline);
        details.setId("incident-information-tab");timeline.setId("incident-log-timeline-tab");details.setClosable(false);timeline.setClosable(false);
        TabPane body=new TabPane(details,timeline);body.setId("incident-tabs");body.setMinWidth(0);body.setMinHeight(0);VBox.setVgrow(body,Priority.ALWAYS);
        Button refresh=secondaryButton("↻ Làm mới ca",()->loadIncidentDetail(incident.id()));
        Button copy=secondaryButton("Copy ID",()->{var data=new javafx.scene.input.ClipboardContent();data.putString(incident.id());javafx.scene.input.Clipboard.getSystemClipboard().setContent(data);});
        Button fullscreen=secondaryButton("Toàn màn hình",()->{if(incidentStage!=null)incidentStage.setFullScreen(!incidentStage.isFullScreen());});
        fullscreen.setId("incident-fullscreen");fullscreen.setAccessibleText("Bật hoặc thoát toàn màn hình incident (F11)");
        return List.of(new HBox(8,refresh,copy,fullscreen),body);
    }
    private String localBusinessTime(LocalDateTime value){return value==null?"—":TIME.format(value.atOffset(ZoneOffset.UTC).atZoneSameInstant(java.time.ZoneId.of("Asia/Ho_Chi_Minh")).toLocalDateTime());}
    private String observedValues(SiemModels.InvestigationSummary view,String field) {
        var group=view.observed().get(field);if(group==null||group.values().isEmpty())return "Không ghi nhận";
        String values=group.values().stream().limit(2).map(SiemModels.ObservedValue::value).collect(java.util.stream.Collectors.joining(", "));
        return values+(group.values().size()>2||group.hasMore()?" … ["+group.values().size()+(group.hasMore()?"+":"")+"]":"");
    }
    private String observedDetails(SiemModels.InvestigationSummary view) {
        return view.observed().entrySet().stream().filter(e->!e.getValue().values().isEmpty())
            .map(e->e.getKey()+": "+e.getValue().values().stream().map(v->v.value()+" ["+v.index()+"/"+v.id()+"]").collect(java.util.stream.Collectors.joining(", "))+(e.getValue().hasMore()?" (+ thêm giá trị)":""))
            .collect(java.util.stream.Collectors.joining("\n"));
    }
    private static final class FlowPaneActions extends javafx.scene.layout.FlowPane {
        FlowPaneActions(){super(8,8);}void add(Node node){getChildren().add(node);}
    }

    private String incidentNatureLabel(String nature) {
        return switch (safe(nature)) {
            case "SECURITY_DETECTION" -> "Security detection";
            case "ELASTIC_DETECTION" -> "Elastic detection";
            case "ACCOUNT_BEHAVIOR_ANOMALY" -> "Account behavior anomaly";
            case "OPERATIONAL_ANOMALY" -> "Operational anomaly";
            case "MIXED_ANOMALY" -> "Mixed security / operations";
            default -> "Unclassified";
        };
    }

    static String geoSummary(List<SiemModels.ElasticDocument> documents) {
        for (SiemModels.ElasticDocument document : documents) {
            Object country = nested(document.source(), "source", "geo", "country_name");
            Object city = nested(document.source(), "source", "geo", "city_name");
            Object asn = nested(document.source(), "source", "as", "number");
            if (country != null) {
                return "GeoIP " + (city == null ? "" : city + ", ") + country
                        + (asn == null ? "" : " · ASN " + asn);
            }
            Object scope = nested(document.source(), "flare", "source_ip_scope");
            if (scope != null) return "GeoIP không áp dụng cho IP " + scope + ".";
        }
        return "Chưa có dữ liệu GeoIP liên quan trong Elasticsearch.";
    }

    private static Object nested(Map<String, Object> source, String... keys) {
        Object direct = source.get(String.join(".", keys));
        if (direct != null) return direct;
        Object current = source;
        for (String key : keys) {
            if (!(current instanceof Map<?, ?> values)) return null;
            current = values.get(key);
        }
        return current;
    }

    private void update(SiemModels.Incident incident, String status, String conclusion,
                        String note, boolean override, Label error) {
        error.setText("");
        api.updateIncident(incident, status, conclusion, note, override)
                .whenComplete((updated, failure) -> Platform.runLater(() -> {
                    if (failure != null) error.setText(message(failure));
                    else { refreshIncidents(); loadIncidentDetail(updated.id()); }
                }));
    }

    private boolean isHigherTierUser() {
        String role=SiemModels.socRole(signedInUser);
        return "ADMIN".equals(role)||"L2".equals(role);
    }

    private void transition(SiemModels.Incident incident, String action, String reason,
                            String conclusion, Label error) {
        error.setText("");
        api.transitionIncident(incident, action, reason, conclusion)
                .whenComplete((updated, failure) -> Platform.runLater(() -> {
                    if(signingOut || !Objects.equals(openIncidentId,incident.id()))return;
                    if (failure != null) {
                        error.setText(message(failure));
                        if (isConflict(failure)) loadIncidentDetail(incident.id());
                    } else {
                        if(draftNote!=null && Objects.equals(draftNote.getText(),reason))draftNote.clear();
                        refreshIncidents();
                        loadIncidentDetail(updated.id());
                    }
                }));
    }

    private void confirmSessionRevocation(SiemModels.Incident incident, Label error) {
        TextInputDialog reasonDialog = new TextInputDialog();
        reasonDialog.setTitle("Revoke customer sessions");
        reasonDialog.setHeaderText("Account " + safe(incident.targetUserId()));
        reasonDialog.setContentText("Investigation reason (at least 10 characters):");
        String reason = reasonDialog.showAndWait().orElse("").trim();
        if (reason.isBlank()) return;
        if (reason.length() < 10) {
            error.setText("Enter a specific reason of at least 10 characters.");
            return;
        }
        Alert confirmation = new Alert(Alert.AlertType.CONFIRMATION,
                "Invalidate all current sessions for customer " + incident.targetUserId()
                        + "? The customer can sign in again afterward.", ButtonType.CANCEL, ButtonType.OK);
        confirmation.setTitle("Confirm SOC L2 response");
        confirmation.setHeaderText("Manual customer-session revocation");
        if (confirmation.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) return;
        String retryKey = incident.id() + ":" + incident.version() + ":" + reason;
        String requestId = pendingRevocationIds.computeIfAbsent(retryKey,
                ignored -> UUID.randomUUID().toString());
        error.setText("Revoking customer sessions…");
        api.revokeCustomerSessions(incident, reason, requestId)
                .whenComplete((result, failure) -> Platform.runLater(() -> {
                    if (failure != null) {
                        error.setText(message(failure));
                        if (isConflict(failure)) {
                            pendingRevocationIds.remove(retryKey);
                            loadIncidentDetail(incident.id());
                        }
                    } else {
                        pendingRevocationIds.remove(retryKey);
                        refreshIncidents();
                        loadIncidentDetail(result.incidentId());
                    }
                }));
    }

    private boolean isConflict(Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof com.flarefitness.monitor.api.SiemApiException apiError
                    && apiError.getStatusCode() == 409) return true;
            current = current.getCause();
        }
        return false;
    }

    private Node logTable(List<SiemModels.ElasticDocument> items) {
        TableView<SiemModels.ElasticDocument> table = new TableView<>();
        table.getColumns().add(column("Time / source document", 260, SiemModels.ElasticDocument::id));
        table.getColumns().add(column("Index", 230, SiemModels.ElasticDocument::index));
        table.getColumns().add(column("ECS fields", 720, item -> "Use ELK Discover for the native document"));
        table.getItems().setAll(items);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        return table;
    }

    private Node geoTable(List<SiemModels.GeoBucket> items) {
        TableView<SiemModels.GeoBucket> table = new TableView<>();
        table.getColumns().add(column("Country", 250, item -> item.countryName() + " (" + item.countryCode() + ")"));
        table.getColumns().add(column("Latitude", 160, SiemModels.GeoBucket::latitude));
        table.getColumns().add(column("Longitude", 160, SiemModels.GeoBucket::longitude));
        table.getColumns().add(column("Events", 180, SiemModels.GeoBucket::count));
        table.getItems().setAll(items);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        return table;
    }

    private void loadAccountBehavior(String accountId, VBox detail) {
        long generation = ++accountDetailGeneration;
        detail.getChildren().setAll(stateLabel("Loading behavior timeline…", "muted"));
        LocalDateTime to = LocalDateTime.now(ZoneOffset.UTC);
        api.accountBehavior(accountId, to.minusDays(7), to)
                .whenComplete((page, failure) -> Platform.runLater(() -> {
                    if (!"watchlist".equals(currentView) || generation != accountDetailGeneration
                            || watchPane == null || !accountId.equals(watchPane.selectedAccountId())) return;
                    if (failure != null) {
                        detail.getChildren().setAll(stateLabel(message(failure), "error-text"));
                        return;
                    }
                    detail.getChildren().setAll(
                            stateLabel("ACCOUNT " + accountId, "detail-title"),
                            stateLabel("Most recent 100 windows · timestamps in UTC", "muted"));
                    if (page.content().isEmpty()) {
                        detail.getChildren().add(stateLabel("No behavior windows in this range.", "muted"));
                    }
                    page.content().forEach(window -> detail.getChildren().add(stateLabel(
                            safeTime(window.windowStart()) + " · Risk "
                                    + (window.riskScore() == null ? "pending" : window.riskScore())
                                    + " · " + safe(window.scoreStatus())
                                    + "\nModel " + safe(window.modelVersion())
                                    + " · percentile " + (window.anomalyPercentile() == null
                                            ? "—" : String.format("%.2f", window.anomalyPercentile()))
                                    + " · baseline " + (window.baselineEstablished() ? "ready" : "insufficient")
                                    + " · data " + safe(window.demoLabel())
                                    + "\nIP " + safe(window.sourceIp()) + " · UA " + safe(window.userAgentFamily())
                                    + "\n" + BehaviorSignalSummary.describe(window)
                                    + "\nFeatures " + window.features()
                                    + "\nSignals " + safe(window.riskReasons()), "note-card")));
                }));
    }

    private Node historyTable(List<SiemModels.History> items) {
        TableView<SiemModels.History> table = new TableView<>();
        table.getColumns().add(column("Time", 150, item -> TIME.format(item.createdAt())));
        table.getColumns().add(column("Action", 180, SiemModels.History::action));
        table.getColumns().add(column("Actor", 180, SiemModels.History::actorUserId));
        table.getColumns().add(column("Incident", 260, SiemModels.History::incidentId));
        table.getColumns().add(column("Detail", 350, item -> safe(item.detail())));
        table.getItems().setAll(items);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        return table;
    }

    private Node settingsPanel(SettingsData data) {
        VBox root = new VBox(14);
        root.getStyleClass().add("panel");
        Label state = stateLabel(data.status.enabled() ? "SIEM integration enabled" : "SIEM integration disabled",
                data.status.elasticsearchAvailable() ? "status-ok" : "status-error");
        Label checkpoint = stateLabel("Last sync: " + safeTime(data.status.lastSuccessAt())
                + "\nLast error: " + safe(data.status.lastError()), "detail-meta");
        Label modelState = stateLabel("UEBA worker: " + (data.ueba.workerAvailable() ? "ONLINE" : "OFFLINE")
                + " · Model: " + (data.ueba.modelAvailable()
                        ? safe(data.ueba.activeModelVersion()) : "NOT READY")
                + (data.ueba.activeModelProvenance() == null ? ""
                        : " · data " + data.ueba.activeModelProvenance())
                + "\nFeature schema: v" + data.ueba.featureSchemaVersion()
                + " · queues: aggregate " + data.ueba.pendingAggregationEvents()
                + ", export " + data.ueba.pendingExportEvents()
                + ", score " + data.ueba.pendingScoringWindows()
                + (data.ueba.reason() == null ? "" : " · " + data.ueba.reason()), "detail-meta");
        TextField windowName = new TextField();
        windowName.setPromptText("Window name (e.g. Authorized scanner demo)");
        TextField sourceIp = new TextField();
        sourceIp.setPromptText("Optional source IP");
        TextField serviceId = new TextField();
        serviceId.setPromptText("Optional service ID");
        Label windowError = stateLabel("", "error-text");
        Button declare = actionButton("Declare 60-minute test", () -> {
            if (windowName.getText().isBlank()) {
                windowError.setText("Window name is required.");
                return;
            }
            LocalDateTime starts = LocalDateTime.now(ZoneOffset.UTC);
            api.createTestWindow(windowName.getText(), sourceIp.getText(), serviceId.getText(), starts, starts.plusHours(1))
                    .whenComplete((created, failure) -> Platform.runLater(() -> {
                        if (failure != null) windowError.setText(message(failure)); else showSettings();
                    }));
        });
        HBox windowForm = new HBox(8, windowName, sourceIp, serviceId, declare);
        HBox.setHgrow(windowName, Priority.ALWAYS);
        TableView<SiemModels.TestWindow> table = new TableView<>();
        table.getColumns().add(column("Name", 220, SiemModels.TestWindow::name));
        table.getColumns().add(column("Source", 150, item -> safe(item.sourceIp())));
        table.getColumns().add(column("Service", 170, item -> safe(item.serviceId())));
        table.getColumns().add(column("Starts", 160, item -> safeTime(item.startsAt())));
        table.getColumns().add(column("Ends", 160, item -> safeTime(item.endsAt())));
        table.getColumns().add(column("Active", 90, SiemModels.TestWindow::active));
        table.getItems().setAll(data.windows);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        Button endSelected = actionButton("End selected window", () -> {
            SiemModels.TestWindow selected = table.getSelectionModel().getSelectedItem();
            if (selected == null) {
                windowError.setText("Select an active test window first.");
                return;
            }
            api.endTestWindow(selected).whenComplete((ended, failure) -> Platform.runLater(() -> {
                if (failure != null) windowError.setText(message(failure)); else showSettings();
            }));
        });
        root.getChildren().addAll(state, checkpoint, stateLabel("ACCOUNT BEHAVIOR MODEL", "eyebrow"), modelState);
        if (isAdminUser()) {
            if (lastTrainingJob == null && !data.jobs().content().isEmpty()) lastTrainingJob = data.jobs().content().getFirst();
            if (lastTrainingJob != null) {
                String selectedId = lastTrainingJob.id();
                data.jobs().content().stream().filter(job -> job.id().equals(selectedId)).findFirst()
                        .ifPresent(job -> lastTrainingJob = job);
            }
            root.getChildren().add(uebaAdminActions(data.jobs(), data.recipes()));
            root.getChildren().add(shadowAdminActions(data.shadows()));
        }
        root.getChildren().add(stateLabel("DECLARED TEST WINDOWS", "eyebrow"));
        if (isAdminUser()) root.getChildren().addAll(windowForm, endSelected, windowError);
        root.getChildren().add(table);
        VBox.setVgrow(table, Priority.ALWAYS);
        return root;
    }

    private Node uebaAdminActions(SiemModels.Page<SiemModels.UebaTrainingJob> jobs, List<SiemModels.UebaRecipe> recipes) {
        long generation = settingsGeneration;
        Label progress = stateLabel(lastTrainingJob == null ? "No training job has been recorded yet."
                : "Model " + lastTrainingJob.modelVersion() + " · " + lastTrainingJob.status()
                        + " · " + safe(lastTrainingJob.dataProvenance())
                        + " · train " + lastTrainingJob.trainingWindows()
                        + " / calibration " + lastTrainingJob.calibrationWindows()
                        + " · evaluation " + safe(lastTrainingJob.evaluationStatus())
                        + " · gate " + safe(lastTrainingJob.qualityGate()), "detail-meta");
        ComboBox<SiemModels.UebaRecipe> recipe = new ComboBox<>();
        recipe.setId("ueba-recipe-selector");
        recipe.setPrefWidth(420);
        recipe.getItems().setAll(recipes);
        recipe.setCellFactory(ignored -> recipeCell());
        recipe.setButtonCell(recipeCell());
        if (!recipes.isEmpty()) recipe.getSelectionModel().selectFirst();
        Button trainRecipe = actionButton("Train frozen recipe", () -> {
            if (recipe.getValue() == null) return;
            progress.setText("Training registered recipe; evaluation and activation remain separate…");
            api.startUebaRecipe(recipe.getValue()).whenComplete((job, failure) -> Platform.runLater(() -> {
                if (!settingsCurrent(generation)) return;
                if (failure != null) progress.setText(message(failure)); else { lastTrainingJob = job; showSettings(); }
            }));
        });
        trainRecipe.setDisable(recipes.isEmpty());
        Button train = secondaryButton("Legacy training (past 14 days)", () -> {
            LocalDateTime to = LocalDateTime.now(ZoneOffset.UTC).minusMinutes(15);
            progress.setText("Starting training…");
            api.startUebaTraining(to.minusDays(14), to)
                    .whenComplete((job, failure) -> Platform.runLater(() -> {
                        if (!settingsCurrent(generation)) return;
                        if (failure != null) progress.setText(message(failure));
                        else { lastTrainingJob = job; showSettings(); }
                    }));
        });
        Button refresh = secondaryButton("Refresh training job", () -> {
            if (lastTrainingJob == null) return;
            api.uebaTrainingJob(lastTrainingJob.id())
                    .whenComplete((job, failure) -> Platform.runLater(() -> {
                        if (!settingsCurrent(generation)) return;
                        if (failure != null) progress.setText(message(failure));
                        else { lastTrainingJob = job; showSettings(); }
                    }));
        });
        refresh.setDisable(lastTrainingJob == null);
        Button evaluate = actionButton("Evaluate frozen holdout", () -> {
            if (lastTrainingJob == null || !lastTrainingJob.canEvaluate()) return;
            String dataset = lastTrainingJob.datasetId() != null ? lastTrainingJob.datasetId()
                    : recipe.getValue() == null ? null : recipe.getValue().datasetId();
            if (dataset == null) { progress.setText("No operator-registered holdout dataset is available."); return; }
            Alert confirmation = new Alert(Alert.AlertType.CONFIRMATION,
                    "Evaluate this candidate once against the frozen DEMO_ONLY holdout? This does not activate it.",
                    ButtonType.CANCEL, ButtonType.OK);
            confirmation.setHeaderText("Independent model-only evaluation");
            if (confirmation.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) return;
            api.evaluateUebaModel(lastTrainingJob.modelVersion(), dataset).whenComplete((job, failure) -> Platform.runLater(() -> {
                if (!settingsCurrent(generation)) return;
                if (failure != null) progress.setText(message(failure)); else { lastTrainingJob = job; showSettings(); }
            }));
        });
        evaluate.setDisable(lastTrainingJob == null || !lastTrainingJob.canEvaluate() || recipes.isEmpty());
        Button activate = actionButton("Activate candidate", () -> {
            if (lastTrainingJob == null || !lastTrainingJob.canActivate()) return;
            Alert confirmation = new Alert(Alert.AlertType.CONFIRMATION,
                    "Activate model " + lastTrainingJob.modelVersion() + " for new behavior windows?",
                    ButtonType.CANCEL, ButtonType.OK);
            confirmation.setHeaderText("Confirm UEBA model activation");
            if (confirmation.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) return;
            api.activateUebaModel(lastTrainingJob.modelVersion())
                    .whenComplete((job, failure) -> Platform.runLater(() -> {
                        if (!settingsCurrent(generation)) return;
                        if (failure != null) progress.setText(message(failure));
                        else { lastTrainingJob = job; showSettings(); }
                    }));
        });
        activate.setId("ueba-activate-candidate");
        activate.setDisable(lastTrainingJob == null || !lastTrainingJob.canActivate());
        TableView<SiemModels.UebaTrainingJob> candidates = new TableView<>();
        candidates.setPrefHeight(180);
        candidates.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        candidates.getColumns().add(column("Model version", 245, SiemModels.UebaTrainingJob::modelVersion));
        candidates.getColumns().add(column("Status", 105, SiemModels.UebaTrainingJob::status));
        candidates.getColumns().add(column("Training data", 125, SiemModels.UebaTrainingJob::dataProvenance));
        candidates.getColumns().add(column("Evaluation", 105, SiemModels.UebaTrainingJob::evaluationStatus));
        candidates.getColumns().add(column("Quality gate", 105, SiemModels.UebaTrainingJob::qualityGate));
        candidates.getColumns().add(column("Train / calibration", 150,
                job -> job.trainingWindows() + " / " + job.calibrationWindows()));
        candidates.getColumns().add(column("Created", 160,
                job -> safeTime(job.createdAt())));
        candidates.getItems().setAll(jobs.content());
        candidates.getSelectionModel().selectedItemProperty().addListener((ignored, old, selected) -> {
            if (selected != null) { lastTrainingJob = selected; showSettings(); }
        });
        return new VBox(8, progress, new HBox(8, recipe, trainRecipe), new HBox(8, train, refresh, evaluate, activate),
                stateLabel(modelMetrics(lastTrainingJob), "note-card"),
                stateLabel("DEMO_ONLY results describe this lab, not production accuracy. A percentile is not a probability of compromise.", "muted"),
                stateLabel("MODEL CANDIDATES · Select a retired model to restore it", "eyebrow"),
                pageControls(jobs, () -> { trainingPage--; showSettings(); }, () -> { trainingPage++; showSettings(); }), candidates);
    }

    private Node shadowAdminActions(SiemModels.Page<SiemModels.UebaShadowRun> page) {
        long generation = settingsGeneration;
        Label message = stateLabel("Candidate-only observation: real 24 hours, at least 600 new closed windows; no response actions.", "muted");
        Button start = actionButton("Start candidate shadow", () -> {
            SiemModels.UebaTrainingJob selected = lastTrainingJob;
            if (selected == null || !selected.canStartShadow()) return;
            Alert confirmation = new Alert(Alert.AlertType.CONFIRMATION,
                    "Observe " + selected.modelVersion() + " for at least 24 real hours? The primary model stays unchanged.", ButtonType.CANCEL, ButtonType.OK);
            confirmation.setHeaderText("Start isolated candidate observation");
            if (confirmation.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK || !settingsCurrent(generation)) return;
            api.startUebaShadow(selected.modelVersion()).whenComplete((run, failure) -> Platform.runLater(() -> {
                if (!settingsCurrent(generation)) return;
                if (failure != null) message.setText(message(failure)); else { shadowPage = 0; showSettings(); }
            }));
        });
        start.setId("ueba-start-shadow"); start.setDisable(lastTrainingJob == null || !lastTrainingJob.canStartShadow());
        Button refresh = secondaryButton("Refresh shadow runs", this::showSettings);
        TableView<SiemModels.UebaShadowRun> table = new TableView<>(); table.setId("ueba-shadow-runs"); table.setPrefHeight(180);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.getColumns().add(column("Candidate", 245, SiemModels.UebaShadowRun::modelVersion));
        table.getColumns().add(column("Status", 110, SiemModels.UebaShadowRun::status));
        table.getColumns().add(column("Elapsed", 95, run -> String.format(java.util.Locale.ROOT, "%.2f / 24 h", run.elapsedSeconds() / 3600)));
        table.getColumns().add(column("Scored", 95, run -> run.closedWindows() + " / 600"));
        table.getColumns().add(column("Backend ACK", 110, SiemModels.UebaShadowRun::acknowledgedWindows));
        table.getColumns().add(column("Last error", 165, run -> safe(run.lastErrorType())));
        table.getItems().setAll(page.content());
        table.getSelectionModel().selectedItemProperty().addListener((ignored, old, run) -> {
            if (run == null) return;
            message.setText("Run " + run.id() + " · " + safe(run.dataProvenance()) + "\nClock "
                    + (run.state() == null ? "—" : run.state().getOrDefault("clock_provenance", "not started"))
                    + " · maximum heartbeat gap " + (run.state() == null ? "—" : run.state().getOrDefault("maximum_heartbeat_gap_seconds", "—"))
                    + " seconds\nCOMPLETED proves lab operation, not production accuracy. Primary is unchanged by shadow.");
        });
        return new VBox(8, stateLabel("CANDIDATE SHADOW · NO ACTIONS", "eyebrow"), new HBox(8, start, refresh), message,
                pageControls(page, () -> { shadowPage--; showSettings(); }, () -> { shadowPage++; showSettings(); }), table);
    }

    private Node pageControls(SiemModels.Page<?> page, Runnable previousAction, Runnable nextAction) {
        Button previous = secondaryButton("Previous", previousAction); previous.setDisable(page.page() == 0);
        Button next = secondaryButton("Next", nextAction); next.setDisable(!page.hasNext());
        return new HBox(8, previous, stateLabel("Page " + (page.page() + 1) + " / " + Math.max(1, page.totalPages())
                + " · " + page.totalElements() + " records", "muted"), next);
    }

    private boolean settingsCurrent(long generation) {
        return !signingOut && "settings".equals(currentView) && settingsGeneration == generation;
    }

    private static ListCell<SiemModels.UebaRecipe> recipeCell() {
        return new ListCell<>() {
            { getStyleClass().add("baseline-view-cell"); }
            @Override protected void updateItem(SiemModels.UebaRecipe value, boolean empty) {
                super.updateItem(value, empty);
                setText(empty || value == null ? null : value.recipeId() + " · " + value.completedSearchFits() + " search fits");
            }
        };
    }

    static String modelMetrics(SiemModels.UebaTrainingJob job) {
        if (job == null) return "No independent model evaluation yet.";
        if ("LEGACY_RESTORE".equals(job.qualityGate())) return "Legacy restore only — not evaluated under the new quality gate.";
        if (job.evaluationSummary() == null || job.evaluationSummary().isEmpty()) return "No independent model evaluation yet.";
        try {
            var scopes = com.flarefitness.monitor.model.UebaQualityMetrics.from(job.evaluationSummary());
            if (scopes.isEmpty()) return "No completed independent evaluation metrics yet.";
            StringBuilder text = new StringBuilder();
            for (var scope : scopes) {
                if (!text.isEmpty()) text.append("\n\n");
                var counts = scope.counts();
                text.append(scope.name().replace('_', ' ')).append(" · ").append(scope.qualityGate())
                        .append("\nRecall ").append(metricPercent(counts.recall())).append(" · false-positive rate ").append(metricPercent(counts.fpr()))
                        .append(" · precision ").append(metricPercent(counts.precision())).append(" · accuracy ").append(metricPercent(counts.accuracy()))
                        .append("\nTP ").append(counts.tp()).append(" / FP ").append(counts.fp()).append(" / TN ").append(counts.tn()).append(" / FN ").append(counts.fn())
                        .append("\nNormal ").append(counts.normal()).append(" · abnormal ").append(counts.positive())
                        .append("\nConservative confidence: precision ").append(metricBounds(scope.precision()))
                        .append(" · recall ").append(metricBounds(scope.recall())).append(" · FPR ").append(metricBounds(scope.falsePositiveRate()));
            }
            return text.toString();
        } catch (RuntimeException invalid) { return "Invalid evaluation counters or confidence bounds; not a verified quality result."; }
    }
    private static String metricBounds(com.flarefitness.monitor.model.UebaQualityMetrics.Bounds bounds) {
        return bounds.available() ? "[" + metricPercent(bounds.lower()) + ", " + metricPercent(bounds.upper()) + "]" : "unavailable";
    }
    private static String metricPercent(Object value) {
        return value instanceof Number number && Double.isFinite(number.doubleValue())
                ? String.format(java.util.Locale.ROOT, "%.5f%%", number.doubleValue() * 100) : "undefined";
    }

    private boolean isAdminUser() {
        return "ADMIN".equals(SiemModels.socRole(signedInUser));
    }

    private <T, R> TableColumn<T, R> column(String name, double width, Function<T, R> mapper) {
        TableColumn<T, R> column = new TableColumn<>(name);
        column.setPrefWidth(width);
        column.setCellValueFactory(cell -> new ReadOnlyObjectWrapper<>(mapper.apply(cell.getValue())));
        return column;
    }

    @SafeVarargs
    private final <T> ComboBox<T> filterBox(T... options) {
        ComboBox<T> box = new ComboBox<>();
        box.getItems().addAll(options);
        box.getSelectionModel().selectFirst();
        return box;
    }

    private void selectFilter(ComboBox<FilterOption> box, String value) {
        box.getItems().stream().filter(option -> Objects.equals(option.value(), value)).findFirst()
                .ifPresent(option -> box.getSelectionModel().select(option));
    }

    private String filterValue(ComboBox<FilterOption> box) {
        FilterOption selected = box == null ? null : box.getValue();
        return selected == null ? null : selected.value();
    }

    private Button secondaryButton(String text, Runnable action) {
        Button button = new Button(text);
        button.getStyleClass().add("secondary-button");
        button.setOnAction(event -> action.run());
        return button;
    }

    private Button actionButton(String text, Runnable action) {
        Button button = new Button(text);
        button.getStyleClass().add("primary-button");
        button.setOnAction(event -> action.run());
        return button;
    }

    private Label stateLabel(String text, String style) {
        Label label = new Label(text);
        label.setWrapText(true);
        label.getStyleClass().add(style);
        return label;
    }

    private void showError(Throwable failure) {
        Label error = stateLabel(message(failure), "error-banner");
        if (contentHost.getChildren().isEmpty()) contentHost.getChildren().add(error);
        else contentHost.getChildren().add(0, error);
    }

    private void setContent(Node node) {
        contentHost.getChildren().setAll(node);
        VBox.setVgrow(node, Priority.ALWAYS);
    }

    private void markRefreshed() { refreshedLabel.setText("Updated " + TIME.format(LocalDateTime.now())); }

    private void cancelDashboardRequests() {
        settingsGeneration++;
        if (settingsRequest != null && !settingsRequest.isDone()) settingsRequest.cancel(true);
        cancelOverviewRequest();
        cancelIncidentRequest();
        watchGeneration++;
        accountDetailGeneration++;
        if (watchRequest != null) watchRequest.cancel(true);
    }

    private void cancelOverviewRequest() {
        overviewGeneration++;
        if (overviewRequest != null && !overviewRequest.isDone()) overviewRequest.cancel(true);
    }

    private void cancelIncidentRequest() {
        incidentGeneration++;
        if (incidentRequest != null && !incidentRequest.isDone()) incidentRequest.cancel(true);
    }

    private String safe(String value) { return value == null || value.isBlank() ? "—" : value; }
    private String safeTime(LocalDateTime value) { return value == null ? "—" : TIME.format(value); }

    public static String message(Throwable failure) {
        Throwable value = failure;
        while ((value instanceof CompletionException || value.getCause() != null) && value.getCause() != null) {
            value = value.getCause();
        }
        return value.getMessage() == null ? value.getClass().getSimpleName() : value.getMessage();
    }

    private record FilterOption(String label, String value) {
        @Override public String toString() { return label; }
    }

    private record SummaryAndPriority(
            SiemModels.DashboardSummary summary,
            SiemModels.Page<SiemModels.Incident> priority
    ) { }

    private record OverviewBase(SummaryAndPriority summaryAndPriority, SiemModels.Status status) { }
    private record OverviewData(SummaryAndPriority summaryAndPriority,
                                SiemModels.Status status,
                                SiemModels.PreventionStatus prevention) { }
    private record SettingsBase(SiemModels.Status status, List<SiemModels.TestWindow> windows) { }
    private record SettingsData(SiemModels.Status status, List<SiemModels.TestWindow> windows,
                                SiemModels.UebaStatus ueba,
                                SiemModels.Page<SiemModels.UebaTrainingJob> jobs, List<SiemModels.UebaRecipe> recipes,
                                SiemModels.Page<SiemModels.UebaShadowRun> shadows) { }
    private record SignatureView(List<SiemModels.AttackSignature> signatures,
                                 SiemModels.PreventionStatus status) { }
    private record IncidentBundle(
            SiemModels.IncidentDetail detail,
            List<SiemModels.AlertRef> alerts,
            List<SiemModels.ElasticDocument> logs,
            List<SiemModels.History> history,
            List<SiemModels.BehaviorWindow> behaviorWindows,
            List<SiemModels.SecurityEventEvidence> securityEvents,
            long totalSecurityEvents,
            List<SiemModels.IpIntelligence> ipIntelligence
    ) { }
}
