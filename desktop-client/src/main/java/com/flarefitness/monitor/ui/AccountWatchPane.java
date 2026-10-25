package com.flarefitness.monitor.ui;

import com.flarefitness.monitor.model.SiemModels;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Function;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.Tooltip;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.SplitPane;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

/** Paginated account inventory; baseline gaps are coverage gaps, never fraud labels. */
public final class AccountWatchPane extends VBox {
    private final ComboBox<ViewOption> filter = new ComboBox<>();
    private final TableView<SiemModels.WatchAccount> table = new TableView<>();
    private final VBox detail = new VBox(9);
    private final Label message = new Label();
    private final Label pageLabel = new Label();
    private final Button previous = new Button("Previous");
    private final Button next = new Button("Next");
    private final Runnable refresh;
    private int page;

    public AccountWatchPane(Runnable refresh, BiConsumer<String, VBox> selectAccount) {
        super(12);
        this.refresh = refresh;
        setId("account-watch-pane");
        filter.setId("baseline-view-filter");
        filter.setPrefWidth(220);
        filter.setButtonCell(viewCell());
        filter.setCellFactory(ignored -> viewCell());
        filter.getItems().setAll(new ViewOption("RISK", "Risk watchlist"),
                new ViewOption("BASELINE_GAPS", "Baseline gaps"), new ViewOption("ALL", "All customers"));
        filter.getSelectionModel().selectFirst();
        filter.valueProperty().addListener((ignored, old, selected) -> { page = 0; refresh.run(); });
        table.setId("account-watch-table");
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.getColumns().add(column("Customer ID", SiemModels.WatchAccount::accountId));
        table.getColumns().add(column("Risk", value ->
                value.riskAvailable() || value.baselineStatus() == null ? value.maximumRisk() : "—"));
        TableColumn<SiemModels.WatchAccount, String> baseline = column("Baseline", value ->
                value.baselineStatus() == null ? "UNKNOWN" : value.baselineStatus());
        baseline.setCellFactory(ignored -> new TableCell<>() {
            @Override protected void updateItem(String value, boolean empty) {
                super.updateItem(value, empty);
                if (empty || value == null) { setGraphic(null); setText(null); return; }
                Label badge = new Label(switch (value) {
                    case "READY" -> "Ready";
                    case "NO_DATA" -> "No data";
                    case "INSUFFICIENT_HISTORY" -> "Learning";
                    default -> "Unknown";
                });
                badge.setTooltip(new Tooltip(value.replace('_', ' ') + " · 30 trusted windows in 14 days"));
                badge.getStyleClass().add("READY".equals(value) ? "baseline-ready" : "baseline-gap");
                setText(null);
                setGraphic(badge);
            }
        });
        table.getColumns().add(baseline);
        table.getColumns().add(column("Trusted history", value -> value.baselineStatus() == null ? "—"
                : value.trustedWindowCount() + "/" + value.requiredWindowCount()));
        table.getColumns().add(column("Flagged windows", SiemModels.WatchAccount::flaggedWindows));
        table.getColumns().add(column("Last activity (UTC)", value -> value.lastWindow() == null ? "—"
                : DateTimeFormatter.ofPattern("dd/MM HH:mm").format(value.lastWindow())));
        int[] widths = {210, 65, 105, 120, 115, 155};
        for (int index = 0; index < widths.length; index++) table.getColumns().get(index).setPrefWidth(widths[index]);
        table.getSelectionModel().selectedItemProperty().addListener((ignored, old, selected) -> {
            if (selected != null) selectAccount.accept(selected.accountId(), detail);
            else detail.getChildren().setAll(new Label("Select a customer to inspect behavior windows."));
        });
        detail.getStyleClass().add("detail-panel");
        detail.getChildren().add(new Label("Select a customer to inspect behavior windows."));
        ScrollPane scroll = new ScrollPane(detail);
        scroll.setFitToWidth(true);
        SplitPane split = new SplitPane(table, scroll);
        split.setDividerPositions(0.60);
        previous.setId("watch-previous-page");
        next.setId("watch-next-page");
        previous.setDisable(true);
        next.setDisable(true);
        previous.setOnAction(ignored -> { if (page > 0) { page--; refresh.run(); } });
        next.setOnAction(ignored -> { if (!next.isDisabled()) { page++; refresh.run(); } });
        Label explanation = new Label("Baseline needs 30 trusted, completed windows in the previous 14 days. "
                + "Missing history is not suspicious behavior. " + BehaviorSignalSummary.CAUTION);
        explanation.setWrapText(true);
        explanation.getStyleClass().add("muted");
        getChildren().setAll(new HBox(12, new Label("View"), filter), explanation, message,
                split, new HBox(12, previous, pageLabel, next));
        VBox.setVgrow(split, Priority.ALWAYS);
    }

    public String view() { return filter.getValue().value(); }
    public int page() { return page; }
    public String selectedAccountId() {
        var selected = table.getSelectionModel().getSelectedItem();
        return selected == null ? null : selected.accountId();
    }

    public void loading() {
        message.setText("Loading customer coverage and risk…");
        message.getStyleClass().remove("error-text");
        previous.setDisable(true);
        next.setDisable(true);
    }

    public void error(String reason) {
        message.setText(reason);
        if (!message.getStyleClass().contains("error-text")) message.getStyleClass().add("error-text");
    }

    public void accept(SiemModels.Page<SiemModels.WatchAccount> result) {
        String selected = selectedAccountId();
        page = result.page();
        table.getItems().setAll(result.content());
        if (selected != null) result.content().stream().filter(item -> Objects.equals(selected, item.accountId()))
                .findFirst().ifPresent(item -> table.getSelectionModel().select(item));
        message.getStyleClass().remove("error-text");
        message.setText(result.content().isEmpty() ? "No customers match this view." : "Baseline snapshot as of "
                + (result.content().getFirst().baselineAsOf() == null ? "unknown"
                : result.content().getFirst().baselineAsOf() + " UTC"));
        pageLabel.setText("Page " + (page + 1) + " / " + Math.max(1, result.totalPages())
                + " · " + result.totalElements() + " customers");
        previous.setDisable(page == 0);
        next.setDisable(!result.hasNext());
    }

    private static <T> TableColumn<SiemModels.WatchAccount, T> column(
            String title, Function<SiemModels.WatchAccount, T> value) {
        TableColumn<SiemModels.WatchAccount, T> column = new TableColumn<>(title);
        column.setCellValueFactory(cell -> new ReadOnlyObjectWrapper<>(value.apply(cell.getValue())));
        return column;
    }

    private record ViewOption(String value, String label) {
        @Override public String toString() { return label; }
    }

    private static ListCell<ViewOption> viewCell() {
        return new ListCell<>() {
            { getStyleClass().add("baseline-view-cell"); }
            @Override protected void updateItem(ViewOption item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? null : item.label());
            }
        };
    }
}
