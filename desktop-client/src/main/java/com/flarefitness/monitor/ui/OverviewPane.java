package com.flarefitness.monitor.ui;

import com.flarefitness.monitor.model.SiemModels;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Consumer;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.geometry.Pos;
import javafx.scene.chart.*;
import javafx.scene.control.*;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.*;

/** Operational overview: actionable queue first; distributions retain every category. */
public class OverviewPane extends VBox {
    private final ComboBox<RangeOption> range=new ComboBox<>();
    private final Label staleLabel=new Label();
    private final Label open=value(),high=value(),l2=value(),pending=value();
    private final TableView<SiemModels.Incident> priorityTable=new TableView<>();
    private final Map<String,SiemModels.InvestigationQueueEntry> evidence=new HashMap<>();
    private final VBox severity=new VBox(8),origin=new VBox(8);
    private final BarChart<String,Number> trend=new BarChart<>(new CategoryAxis(),new NumberAxis());
    private final Consumer<ChartFilter> onFilter;
    public OverviewPane(Consumer<ChartFilter> onFilter,Consumer<SiemModels.Incident> onIncident,Runnable onRefresh,Runnable onRangeChanged){
        super(12);this.onFilter=onFilter;getStyleClass().add("overview-pane");
        range.getItems().addAll(new RangeOption("1 giờ",1),new RangeOption("24 giờ",24),new RangeOption("7 ngày",168));range.getSelectionModel().select(1);range.setOnAction(e->onRangeChanged.run());
        staleLabel.getStyleClass().add("stale-banner");staleLabel.setManaged(false);staleLabel.setVisible(false);
        HBox metrics=new HBox(12,card("CA ĐANG MỞ",open),card("HIGH / URGENT ĐANG MỞ",high),card("L2 ĐANG MỞ",l2),card("RESPONSE CHỜ / LỖI",pending));metrics.getChildren().forEach(n->HBox.setHgrow(n,Priority.ALWAYS));
        Label heading=new Label("Cần xử lý trước");heading.getStyleClass().add("section-title");
        priorityTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);priorityTable.setPrefHeight(260);priorityTable.setFixedCellSize(44);
        priorityTable.getColumns().add(column("Mức độ",90,SiemModels.Incident::severity));priorityTable.getColumns().add(column("Tình huống",320,item->{var view=evidence.get(item.id());return view==null?IncidentPresentation.scenario(item):IncidentPresentation.scenario(item,view.observed(),view.sourceStatus());}));
        priorityTable.getColumns().add(column("IP nguồn",140,SiemModels.Incident::sourceIp));priorityTable.getColumns().add(column("Trạng thái",130,SiemModels.Incident::status));
        priorityTable.getColumns().add(column("Người nhận",180,IncidentPresentation::assignee));
        priorityTable.getColumns().add(column("Thời gian xảy ra",150,item->{var view=evidence.get(item.id());return IncidentPresentation.occurredAt(item,view!=null&&"AVAILABLE".equals(view.sourceStatus())?view.firstObservedAt():null);}));
        priorityTable.setPlaceholder(new Label("Không có ca mở trong hàng đợi này."));
        priorityTable.setRowFactory(t->{TableRow<SiemModels.Incident> row=new TableRow<>();row.setOnMouseClicked(e->{if(e.getClickCount()==2&&!row.isEmpty())onIncident.accept(row.getItem());});return row;});
        priorityTable.setOnKeyPressed(e->{if(e.getCode()==KeyCode.ENTER&&priorityTable.getSelectionModel().getSelectedItem()!=null){onIncident.accept(priorityTable.getSelectionModel().getSelectedItem());e.consume();}});
        trend.setAnimated(false);trend.setLegendVisible(false);trend.setTitle("Tình huống theo thời gian · giờ Việt Nam");trend.setPrefHeight(220);
        HBox distributions=new HBox(12,panel("Mức độ — tất cả ca trong khoảng",severity),panel("Nguồn phát hiện — tất cả ca trong khoảng",origin));distributions.getChildren().forEach(n->HBox.setHgrow(n,Priority.ALWAYS));
        getChildren().addAll(new HBox(10,new Label("Khoảng thời gian"),range),staleLabel,metrics,heading,priorityTable,trend,distributions);
    }
    public int selectedHours(){return range.getValue()==null?24:range.getValue().hours();}
    public void setLoading(boolean loading){range.setDisable(loading);}
    public void update(SiemModels.DashboardSummary summary,List<SiemModels.Incident> priority){update(summary,priority,null);}
    public void update(SiemModels.DashboardSummary summary,List<SiemModels.Incident> priority,SiemModels.PreventionStatus prevention){
        open.setText(Long.toString(summary.byStatus().entrySet().stream().filter(e->!e.getKey().equals("CLOSED")).mapToLong(Map.Entry::getValue).sum()));
        high.setText("—");l2.setText("—");pending.setText("—");
        distribution(severity,summary.bySeverity(),"severity");distribution(origin,summary.byOrigin()==null?Map.of():summary.byOrigin(),"origin");
        evidence.clear();priorityTable.getItems().setAll(priority.stream().filter(i->!"CLOSED".equals(i.status())).limit(10).toList());staleLabel.setVisible(false);staleLabel.setManaged(false);
    }
    public void updateEvidence(List<SiemModels.InvestigationQueueEntry> page){evidence.clear();page.forEach(item->evidence.put(item.incident().id(),item));priorityTable.refresh();}
    public void updateMetrics(SiemModels.InvestigationMetrics metrics){
        open.setText(Long.toString(metrics.open()));high.setText(Long.toString(metrics.highOpen()));l2.setText(Long.toString(metrics.l2Open()));pending.setText(Long.toString(metrics.responsePendingFailed()));
        XYChart.Series<String,Number> series=new XYChart.Series<>();
        for(var point:metrics.trend()){
            String label=LocalDateTime.parse(point.hour()).atOffset(ZoneOffset.UTC).atZoneSameInstant(ZoneId.of("Asia/Ho_Chi_Minh")).format(DateTimeFormatter.ofPattern("dd/MM HH:mm"));
            series.getData().add(new XYChart.Data<>(label,point.count()));
        }
        trend.getData().setAll(List.of(series));
    }
    public void showRefreshError(String message){staleLabel.setText("Dữ liệu lần tải thành công trước · "+message);staleLabel.setVisible(true);staleLabel.setManaged(true);}
    private void distribution(VBox target,Map<String,Long> counts,String dimension){
        target.getChildren().clear();long total=counts.values().stream().mapToLong(Long::longValue).sum();
        counts.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e->{
            Button name=new Button(e.getKey()+" · "+e.getValue());name.getStyleClass().add("distribution-label");name.setOnAction(event->onFilter.accept(new ChartFilter(dimension,e.getKey())));
            ProgressBar bar=new ProgressBar(total==0?0:(double)e.getValue()/total);bar.setMaxWidth(Double.MAX_VALUE);HBox.setHgrow(bar,Priority.ALWAYS);
            HBox line=new HBox(12,name,bar);line.setAlignment(Pos.CENTER_LEFT);target.getChildren().add(line);
        });
        if(total==0)target.getChildren().add(new Label("Chưa có dữ liệu."));
    }
    private static Label value(){Label label=new Label("—");label.getStyleClass().add("metric-value");return label;}
    private static VBox card(String title,Label value){Label caption=new Label(title);caption.getStyleClass().add("metric-label");VBox box=new VBox(8,caption,value);box.setMaxWidth(Double.MAX_VALUE);box.getStyleClass().add("metric-card");return box;}
    private static VBox panel(String title,VBox content){Label label=new Label(title);label.getStyleClass().add("section-title");VBox box=new VBox(12,label,content);box.getStyleClass().add("panel");box.setMaxWidth(Double.MAX_VALUE);return box;}
    private static <T,R> TableColumn<T,R> column(String title,double width,java.util.function.Function<T,R> getter){TableColumn<T,R> c=new TableColumn<>(title);c.setPrefWidth(width);c.setCellValueFactory(v->new ReadOnlyObjectWrapper<>(getter.apply(v.getValue())));return c;}
    public record ChartFilter(String dimension,String value) { }
    private record RangeOption(String label,int hours){@Override public String toString(){return label;}}
}
