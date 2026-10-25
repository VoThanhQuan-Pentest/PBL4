package com.flarefitness.monitor.ui;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import javafx.collections.FXCollections;
import javafx.geometry.Pos;
import javafx.scene.AccessibleRole;
import javafx.scene.chart.PieChart;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;

public class DonutChartCard extends VBox {
    private final PieChart chart = new PieChart();
    private final Label totalLabel = new Label("0");
    private final VBox legend = new VBox(6);
    private final Map<String, String> labels;
    private final Map<String, String> colors;
    private final Consumer<String> onSelected;

    public DonutChartCard(
            String title,
            Map<String, String> labels,
            Map<String, String> colors,
            Consumer<String> onSelected
    ) {
        this.labels = new LinkedHashMap<>(labels);
        this.colors = new LinkedHashMap<>(colors);
        this.onSelected = onSelected;
        getStyleClass().add("donut-card");
        setSpacing(10);
        setMaxWidth(Double.MAX_VALUE);

        Label titleLabel = new Label(title);
        titleLabel.getStyleClass().add("chart-title");
        chart.setLegendVisible(false);
        chart.setLabelsVisible(false);
        chart.setAnimated(false);
        chart.setClockwise(true);
        chart.setStartAngle(90);
        chart.setPrefSize(220, 220);
        chart.setMinSize(190, 190);

        Circle hole = new Circle(54, Color.web("#0e1a29"));
        hole.getStyleClass().add("donut-hole");
        Label totalCaption = new Label("INCIDENTS");
        totalCaption.getStyleClass().add("donut-total-caption");
        totalLabel.getStyleClass().add("donut-total");
        VBox center = new VBox(1, totalLabel, totalCaption);
        center.setAlignment(Pos.CENTER);
        center.setMouseTransparent(true);
        StackPane chartStack = new StackPane(chart, hole, center);
        chartStack.setAlignment(Pos.CENTER);
        VBox.setVgrow(chartStack, Priority.ALWAYS);

        getChildren().addAll(titleLabel, chartStack, legend);
        update(Map.of());
    }

    public void update(Map<String, Long> values) {
        long total = labels.keySet().stream().mapToLong(key -> Math.max(0L, values.getOrDefault(key, 0L))).sum();
        totalLabel.setText(Long.toString(total));
        legend.getChildren().clear();
        if (total == 0) {
            PieChart.Data empty = new PieChart.Data("No data", 1);
            chart.setData(FXCollections.observableArrayList(empty));
            styleSlice(empty, "#334155", null, "No data");
            Label noData = new Label("No incidents in this time range");
            noData.getStyleClass().add("muted");
            legend.getChildren().add(noData);
            return;
        }

        var chartData = FXCollections.<PieChart.Data>observableArrayList();
        labels.forEach((key, label) -> {
            long value = Math.max(0L, values.getOrDefault(key, 0L));
            if (value == 0) return;
            PieChart.Data data = new PieChart.Data(label, value);
            chartData.add(data);
            double percentage = value * 100.0 / total;
            String tooltip = "%s: %d (%.1f%%)".formatted(label, value, percentage);
            styleSlice(data, colors.getOrDefault(key, "#64748b"), key, tooltip);
            legend.getChildren().add(legendButton(key, label, value, percentage));
        });
        chart.setData(chartData);
    }

    private Button legendButton(String key, String label, long value, double percentage) {
        Circle swatch = new Circle(5, Color.web(colors.getOrDefault(key, "#64748b")));
        Label name = new Label(label);
        name.getStyleClass().add("donut-legend-name");
        Label count = new Label("%d · %.1f%%".formatted(value, percentage));
        count.getStyleClass().add("donut-legend-value");
        HBox row = new HBox(7, swatch, name, count);
        row.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(name, Priority.ALWAYS);
        Button button = new Button();
        button.setGraphic(row);
        button.setMaxWidth(Double.MAX_VALUE);
        button.getStyleClass().add("donut-legend-button");
        button.setAccessibleRole(AccessibleRole.BUTTON);
        button.setAccessibleText(label + ", " + value + " incidents");
        button.setOnAction(event -> onSelected.accept(key));
        return button;
    }

    private void styleSlice(PieChart.Data data, String color, String key, String tooltipText) {
        data.nodeProperty().addListener((ignored, oldNode, node) -> {
            if (node == null) return;
            node.setStyle("-fx-pie-color: " + color + ";");
            Tooltip.install(node, new Tooltip(tooltipText));
            if (key != null) {
                node.setAccessibleRole(AccessibleRole.BUTTON);
                node.setAccessibleText(tooltipText);
                node.setOnMouseClicked(event -> onSelected.accept(key));
            }
        });
    }
}
