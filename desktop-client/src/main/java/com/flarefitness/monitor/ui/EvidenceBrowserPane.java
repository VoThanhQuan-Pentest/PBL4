package com.flarefitness.monitor.ui;

import com.fasterxml.jackson.databind.JsonNode;
import com.flarefitness.monitor.api.SiemApiClient;
import com.flarefitness.monitor.controller.DashboardController;
import com.flarefitness.monitor.model.SiemModels;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.input.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;

/** Virtualized page of native Elasticsearch hits, with lazy object/array field expansion. */
public final class EvidenceBrowserPane extends VBox {
    private final SiemApiClient api;
    private final String incident;
    private final TableView<SiemModels.EvidenceItem> table=new TableView<>();
    private final Label status=new Label();
    private final Button next=new Button("Next →");
    private final Set<String> expanded=new HashSet<>();
    private final Map<String,CheckBox> columns=new LinkedHashMap<>();
    private final TextField from=new TextField(),to=new TextField(),trace=new TextField(),ip=new TextField(),account=new TextField();
    private final ComboBox<String> dataset=new ComboBox<>();
    private String cursor;
    private long generation;
    private LocalDateTime queryFrom,queryTo;
    private String queryDataset,queryTrace,queryIp,queryAccount;
    private Consumer<List<SiemModels.EvidenceItem>> onPage=items->{};
    private Consumer<String> onIncident=id->{};
    public EvidenceBrowserPane(SiemApiClient api,String incident) {
        super(10);this.api=api;this.incident=incident;
        setMinHeight(300);
        dataset.getItems().addAll("All datasets","nginx.access","flare.security","flare.prevention");dataset.setValue("All datasets");
        LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC).withNano(0);from.setText(now.minusHours(24).toString());to.setText(now.toString());
        from.setPromptText("From UTC (ISO)");to.setPromptText("To UTC (ISO)");trace.setPromptText("Trace ID");ip.setPromptText("Source IP");account.setPromptText("Account ID");
        from.setPrefColumnCount(17);to.setPrefColumnCount(17);trace.setPrefColumnCount(12);ip.setPrefColumnCount(12);account.setPrefColumnCount(12);
        Button search=new Button("Search");search.setOnAction(e->reload());
        if(incident==null) {
            FlowPane filters=new FlowPane(8,8,from,to,dataset,trace,ip,account,search);
            getChildren().add(filters);
        }
        MenuButton configure=new MenuButton("Columns");
        for(String name:List.of("Time","Dataset","IP","Action / message")) {
            CheckBox check=new CheckBox(name);check.setSelected(true);check.setOnAction(e->table.refresh());columns.put(name,check);
            CustomMenuItem menu=new CustomMenuItem(check,false);configure.getItems().add(menu);
        }
        Button first=new Button("↻ First page");first.setOnAction(e->reload());next.setDisable(true);next.setOnAction(e->load(cursor));
        FlowPane toolbar=new FlowPane(8,8,first,next,configure,status);
        if(incident==null) {
            Button create=new Button("Create incident from selection");create.setOnAction(e->createIncident());toolbar.getChildren().add(create);
        }
        table.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        TableColumn<SiemModels.EvidenceItem,SiemModels.EvidenceItem> column=new TableColumn<>("Elasticsearch events · select rows with Ctrl / Shift");
        column.setCellValueFactory(c->new ReadOnlyObjectWrapper<>(c.getValue()));
        column.setCellFactory(c->new TableCell<>() {
            @Override protected void updateItem(SiemModels.EvidenceItem item,boolean empty) {
                super.updateItem(item,empty);setText(null);setGraphic(empty||item==null?null:eventNode(item));
            }
        });
        table.getColumns().add(column);table.setPlaceholder(new Label("No log in this time range."));
        table.setOnKeyPressed(e->{if(e.getCode()==KeyCode.ENTER){var row=table.getSelectionModel().getSelectedItem();if(row!=null)toggle(row);e.consume();}});
        getChildren().addAll(toolbar,table);VBox.setVgrow(table,Priority.ALWAYS);table.setPrefHeight(420);
        reload();
    }
    public void onPage(Consumer<List<SiemModels.EvidenceItem>> callback) {onPage=callback;}
    public void onIncident(Consumer<String> callback) {onIncident=callback;}
    public void dispose() {generation++;table.getItems().clear();expanded.clear();}
    public void reload() {
        try {queryFrom=LocalDateTime.parse(from.getText().trim());queryTo=LocalDateTime.parse(to.getText().trim());}
        catch(RuntimeException e){status.setText("Use ISO UTC dates, e.g. 2026-10-23T08:00:00");return;}
        queryDataset="All datasets".equals(dataset.getValue())?null:dataset.getValue();queryTrace=trace.getText();queryIp=ip.getText();queryAccount=account.getText();
        cursor=null;expanded.clear();load(null);
    }
    private void load(String after) {
        long request=++generation;status.setText("Loading ELK…");next.setDisable(true);
        if(after==null)table.getItems().clear();
        var future=incident==null?api.evidence(queryFrom,queryTo,queryDataset,queryTrace,queryIp,queryAccount,after):api.incidentEvidence(incident,after);
        future.whenComplete((page,failure)->Platform.runLater(()->{
            if(request!=generation)return;
            if(failure!=null){status.setText((after==null?"":"Showing previous page · ")+DashboardController.message(failure));return;}
            table.getItems().setAll(page.content());cursor=page.nextCursor();next.setDisable(cursor==null);
            status.setText(switch(page.sourceStatus()){
                case "AVAILABLE" -> page.content().size()+" events · ELK · UTC";
                case "NO_DETECTION_LOG" -> "No detection log for this case / workflow fixture.";
                case "UNAVAILABLE" -> "Elasticsearch unavailable; workflow notes remain available.";
                case "DISABLED" -> "Elasticsearch reader disabled.";
                default -> page.sourceStatus();
            });
            onPage.accept(page.content());
        }));
    }
    private String key(SiemModels.EvidenceItem item){return item.elkHit().path("_index").asText()+"/"+item.elkHit().path("_id").asText();}
    private void toggle(SiemModels.EvidenceItem item){if(!expanded.add(key(item)))expanded.remove(key(item));table.refresh();}
    private Node eventNode(SiemModels.EvidenceItem item) {
        JsonNode source=item.elkHit().path("_source");boolean open=expanded.contains(key(item));
        Button arrow=new Button(open?"▲":"▼");arrow.setAccessibleText(open?"Collapse event":"Expand event");arrow.setOnAction(e->toggle(item));
        FlowPane summary=new FlowPane(12,6,arrow);
        if(columns.get("Time").isSelected())summary.getChildren().add(new Label(value(source,"@timestamp")));
        if(columns.get("Dataset").isSelected())summary.getChildren().add(new Label(value(source,"event.dataset")));
        if(columns.get("IP").isSelected())summary.getChildren().add(new Label(value(source,"source.ip")));
        if(columns.get("Action / message").isSelected())summary.getChildren().add(new Label(value(source,"event.action")+" · "+value(source,"message")));
        VBox box=new VBox(8,summary);
        if(open) {
            if(item.association()!=null)box.getChildren().add(new Label("Application association: "+item.association().matchType()+" · "+item.association().provenance()));
            Tab fields=new Tab("Fields",fields(source));fields.setClosable(false);
            Tab json=new Tab("JSON",json(item.elkHit()));json.setClosable(false);
            TabPane tabs=new TabPane(fields,json);tabs.setPrefHeight(300);box.getChildren().add(tabs);
        }
        return box;
    }
    public static String value(JsonNode source,String name) {
        if(source.has(name))return scalar(source.get(name));
        JsonNode node=source;for(String key:name.split("\\."))node=node.path(key);
        return node.isMissingNode()?"Chưa có trong log":scalar(node);
    }
    private static String scalar(JsonNode node){return node.isTextual()?node.textValue():node.toString();}
    private record Field(String name,JsonNode value) { }
    private static TreeItem<Field> field(String name,JsonNode node) {
        TreeItem<Field> item=new TreeItem<>(new Field(name,node));
        if(node.isContainerNode() && !node.isEmpty()) {
            item.getChildren().add(new TreeItem<>());
            item.expandedProperty().addListener((o,old,open)->{
                if(open && item.getChildren().size()==1 && item.getChildren().getFirst().getValue()==null){
                    item.getChildren().clear();
                    if(node.isObject())node.fields().forEachRemaining(e->item.getChildren().add(field(e.getKey(),e.getValue())));
                    else for(int i=0;i<node.size();i++)item.getChildren().add(field("["+i+"]",node.get(i)));
                }
            });
        }
        return item;
    }
    public static Node fields(JsonNode source) {
        TreeTableView<Field> tree=new TreeTableView<>();tree.setColumnResizePolicy(TreeTableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        TreeItem<Field> root=field("_source",source);tree.setRoot(root);root.setExpanded(true);tree.setShowRoot(false);
        TreeTableColumn<Field,String> name=new TreeTableColumn<>("ECS field / key");name.setPrefWidth(280);name.setCellValueFactory(c->new ReadOnlyObjectWrapper<>(c.getValue().getValue().name));
        TreeTableColumn<Field,String> type=new TreeTableColumn<>("Type");type.setPrefWidth(100);type.setCellValueFactory(c->new ReadOnlyObjectWrapper<>(c.getValue().getValue().value.getNodeType().toString().toLowerCase(Locale.ROOT)));
        TreeTableColumn<Field,String> value=new TreeTableColumn<>("Value");value.setPrefWidth(500);value.setCellValueFactory(c->{JsonNode n=c.getValue().getValue().value;return new ReadOnlyObjectWrapper<>(n.isContainerNode()?n.size()+" entries":scalar(n));});
        tree.getColumns().add(name);tree.getColumns().add(type);tree.getColumns().add(value);return tree;
    }
    public static Node json(JsonNode hit) {
        String nativeJson=hit.toPrettyString();TextArea text=new TextArea(nativeJson);text.setEditable(false);text.setWrapText(false);text.setMinHeight(45);text.getStyleClass().add("json-view");
        TextField query=new TextField();query.setPromptText("Find in JSON");Label feedback=new Label();
        Button find=new Button("Find next");find.setOnAction(e->{String q=query.getText();int start=text.getSelection().getEnd();int index=nativeJson.indexOf(q,start);if(index<0)index=nativeJson.indexOf(q);if(index>=0&&!q.isEmpty()){text.selectRange(index,index+q.length());text.requestFocus();feedback.setText("");}else feedback.setText("No match");});query.setOnAction(e->find.fire());
        Button copy=new Button("Copy hit");copy.setOnAction(e->{ClipboardContent data=new ClipboardContent();data.putString(nativeJson);Clipboard.getSystemClipboard().setContent(data);feedback.setText("Copied Elasticsearch hit");});
        Button export=new Button("Export hit…");export.setOnAction(e->{FileChooser chooser=new FileChooser();chooser.setInitialFileName("elk-event.json");var file=chooser.showSaveDialog(text.getScene().getWindow());if(file!=null)try{Files.writeString(file.toPath(),nativeJson,StandardCharsets.UTF_8);feedback.setText("Exported");}catch(Exception ex){feedback.setText("Export failed: "+ex.getClass().getSimpleName());}});
        VBox box=new VBox(8,new FlowPane(8,8,query,find,copy,export,feedback),text);box.setMinHeight(0);VBox.setVgrow(text,Priority.ALWAYS);return box;
    }
    private void createIncident() {
        var selected=List.copyOf(table.getSelectionModel().getSelectedItems());if(selected.isEmpty()||selected.size()>20){status.setText("Select 1–20 events.");return;}
        TextInputDialog title=new TextInputDialog();title.setHeaderText("Create manual investigation from ELK events");title.setContentText("Case title:");
        title.showAndWait().filter(t->!t.isBlank()).ifPresent(t->api.createIncident(t,selected).whenComplete((incident,failure)->Platform.runLater(()->{
            if(failure!=null)status.setText(DashboardController.message(failure));else onIncident.accept(incident.id());
        })));
    }
}
