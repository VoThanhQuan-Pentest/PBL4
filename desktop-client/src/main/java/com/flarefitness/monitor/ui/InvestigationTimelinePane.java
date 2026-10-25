package com.flarefitness.monitor.ui;

import com.flarefitness.monitor.api.SiemApiClient;
import com.flarefitness.monitor.controller.DashboardController;
import com.flarefitness.monitor.model.SiemModels;
import java.time.ZoneOffset;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.*;

/** A virtualized timeline of original ELK events; SOC processing history has a separate completed-case view. */
public final class InvestigationTimelinePane extends VBox {
    private final SiemApiClient api;
    private final String incident;
    private final TableView<SiemModels.TimelineEntry> table=new TableView<>();
    private final VBox inspector=new VBox(8);
    private final Label status=new Label();
    private final CheckBox related=new CheckBox("Thêm context liên quan");
    private final Button next=new Button("Tiếp →");
    private String cursor;
    private java.time.LocalDateTime from,to;
    private long generation;
    private boolean disposed;
    private static final DateTimeFormatter TIME=DateTimeFormatter.ofPattern("dd/MM HH:mm:ss").withZone(ZoneId.of("Asia/Ho_Chi_Minh"));
    public InvestigationTimelinePane(SiemApiClient api,String incident) {
        super(8);this.api=api;this.incident=incident;setMinHeight(0);
        related.setOnAction(e->reload());
        Button refresh=new Button("↻ Làm mới");refresh.setOnAction(e->reload());next.setOnAction(e->load(cursor));next.setDisable(true);
        getStyleClass().add("investigation-timeline");
        TextField start=new TextField(),end=new TextField();start.setPromptText("Từ: dd/MM/yyyy HH:mm");end.setPromptText("Đến: dd/MM/yyyy HH:mm");
        Button apply=new Button("Áp dụng"),clear=new Button("Toàn phạm vi ca");
        FlowPane range=new FlowPane(8,8,new Label("Giờ Việt Nam"),start,end,apply,clear);range.setVisible(false);range.setManaged(false);
        Button time=new Button("Thời gian");time.setOnAction(e->{range.setVisible(!range.isVisible());range.setManaged(range.isVisible());});
        apply.setOnAction(e->{try{
            var format=DateTimeFormatter.ofPattern("dd/MM/uuuu HH:mm").withResolverStyle(java.time.format.ResolverStyle.STRICT);
            var begin=java.time.LocalDateTime.parse(start.getText().trim(),format).atZone(ZoneId.of("Asia/Ho_Chi_Minh")).withZoneSameInstant(ZoneOffset.UTC).toLocalDateTime();
            var finish=java.time.LocalDateTime.parse(end.getText().trim(),format).atZone(ZoneId.of("Asia/Ho_Chi_Minh")).withZoneSameInstant(ZoneOffset.UTC).toLocalDateTime();
            if(!begin.isBefore(finish)||java.time.Duration.between(begin,finish).toDays()>30)throw new IllegalArgumentException();
            from=begin;to=finish;reload();
        }catch(RuntimeException invalid){status.setText("Nhập khoảng thời gian hợp lệ, tối đa30 ngày.");}});
        clear.setOnAction(e->{from=null;to=null;start.clear();end.clear();reload();});
        getChildren().addAll(new FlowPane(8,8,related,time,refresh,next,status),range);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);table.setFixedCellSize(66);table.setMinHeight(100);
        table.setPlaceholder(new Label("Chưa có sự kiện trong phạm vi điều tra."));
        TableColumn<SiemModels.TimelineEntry,SiemModels.TimelineEntry> column=new TableColumn<>("Thời gian · nguồn → đích · tài khoản · sự kiện");
        column.setCellValueFactory(c->new ReadOnlyObjectWrapper<>(c.getValue()));
        column.setCellFactory(c->new TableCell<>(){
            @Override protected void updateItem(SiemModels.TimelineEntry item,boolean empty){super.updateItem(item,empty);setText(null);setGraphic(empty||item==null?null:row(item));}
        });table.getColumns().add(column);
        table.getSelectionModel().selectedItemProperty().addListener((o,old,item)->inspect(item));
        SplitPane split=new SplitPane(table,inspector);split.setOrientation(javafx.geometry.Orientation.VERTICAL);split.setDividerPositions(.58);
        inspector.setMinHeight(100);inspector.getStyleClass().add("timeline-inspector");
        getChildren().add(split);VBox.setVgrow(split,Priority.ALWAYS);reload();
    }
    public void reload(){if(disposed)return;cursor=null;load(null);}
    public void dispose(){disposed=true;generation++;table.getItems().clear();inspector.getChildren().clear();}
    private void load(String token){
        if(disposed)return;long request=++generation;status.setText("Đang tải…");next.setDisable(true);
        String selected=table.getSelectionModel().getSelectedItem()==null?null:table.getSelectionModel().getSelectedItem().id();
        api.incidentTimeline(incident,"ELK",related.isSelected(),token,from,to).whenComplete((page,error)->Platform.runLater(()->{
            if(disposed||request!=generation)return;
            if(error!=null){status.setText(DashboardController.message(error));return;}
            var logs=page.content().stream().filter(item->"ELK".equals(item.kind())&&item.elkHit()!=null).toList();
            table.getItems().setAll(logs);cursor=page.nextCursor();next.setDisable(cursor==null);
            status.setText(switch(page.sourceStatus()){
                case "NO_DETECTION_LOG" -> "Không có log phát hiện trong tình huống này.";
                case "AVAILABLE" -> logs.size()+" sự kiện ELK · giờ Việt Nam";
                case "UNAVAILABLE" -> "Chưa kết nối được Elasticsearch.";
                default -> page.sourceStatus();
            });
            var match=page.content().stream().filter(item->item.id().equals(selected)).findFirst();
            if(match.isPresent()&&logs.contains(match.get()))table.getSelectionModel().select(match.get());else if(!logs.isEmpty())table.getSelectionModel().select(0);else inspect(null);
        }));
    }
    private Node row(SiemModels.TimelineEntry item){
        String time=item.occurredAt()==null?"—":TIME.format(item.occurredAt().toInstant(ZoneOffset.UTC));
        Label first=new Label(time+"  ·  "+item.kind()+(item.association()==null?"":"  ·  "+item.association().matchType()));first.getStyleClass().add("muted");
        Label second=new Label(description(item));second.setMaxWidth(Double.MAX_VALUE);second.setTextOverrun(OverrunStyle.ELLIPSIS);second.setTooltip(new Tooltip(second.getText()));
        VBox row=new VBox(4,first,second);row.setMaxWidth(Double.MAX_VALUE);return row;
    }
    private String description(SiemModels.TimelineEntry item){
        if(item.elkHit()!=null){
            var source=item.elkHit().path("_source");String destination=text(source,"destination.ip");
            if(destination.equals("Không ghi nhận")){String server=text(source,"server.ip");if(!server.equals("Không ghi nhận"))destination="server "+server;}
            String actor=text(source,"user.name");if(actor.equals("Không ghi nhận"))actor=text(source,"user.id");
            if(actor.equals("Không ghi nhận")){String target=text(source,"target.user.id");actor=target.equals("Không ghi nhận")?"—":"target "+target+" (chưa xác thực)";}
            String action=text(source,"event.action");if(action.equals("Không ghi nhận"))action=text(source,"message");
            String detail=text(source,"error.message");if(detail.equals("Không ghi nhận"))detail=text(source,"event.reason");if(detail.equals("Không ghi nhận"))detail=text(source,"message");
            return text(source,"source.ip")+" → "+destination+"  ·  "+actor+"  ·  "+action+" / "+text(source,"event.outcome")+(detail.equals("Không ghi nhận")?"":"  ·  "+detail);
        }
        return "";
    }
    private static String text(com.fasterxml.jackson.databind.JsonNode source,String key){String value=EvidenceBrowserPane.value(source,key);return value.equals("Chưa có trong log")?"Không ghi nhận":value;}
    private void inspect(SiemModels.TimelineEntry item){
        inspector.getChildren().clear();if(item==null){inspector.getChildren().add(new Label("Chọn sự kiện để xem chi tiết."));return;}
        if(item.elkHit()!=null){
            Tab fields=new Tab("Fields",EvidenceBrowserPane.fields(item.elkHit().path("_source")));
            Tab json=new Tab("JSON nguyên bản",EvidenceBrowserPane.json(item.elkHit()));fields.setClosable(false);json.setClosable(false);
            TabPane tabs=new TabPane(fields,json);tabs.setMinHeight(0);inspector.getChildren().add(tabs);VBox.setVgrow(tabs,Priority.ALWAYS);
        }
    }
}
