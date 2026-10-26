package com.flarefitness.monitor.ui;

import com.flarefitness.monitor.api.SiemApiClient;
import javafx.scene.Node;
import javafx.scene.input.KeyEvent;
import javafx.scene.input.MouseEvent;
import javafx.scene.input.ScrollEvent;
import javafx.scene.input.TouchEvent;

/** Only deliberate input counts; table refresh/layout/focus events cannot keep a session alive. */
public final class SessionActivity {
    private SessionActivity() { }
    public static void attach(Node root, SiemApiClient api) {
        root.addEventFilter(KeyEvent.KEY_PRESSED, event -> api.recordUserActivity());
        root.addEventFilter(MouseEvent.MOUSE_PRESSED, event -> api.recordUserActivity());
        root.addEventFilter(MouseEvent.MOUSE_DRAGGED, event -> api.recordUserActivity());
        root.addEventFilter(ScrollEvent.SCROLL, event -> api.recordUserActivity());
        root.addEventFilter(TouchEvent.TOUCH_PRESSED, event -> api.recordUserActivity());
    }
}
