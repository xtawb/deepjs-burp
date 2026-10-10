package deepjs.burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;

/**
 * The "DeepJS" tab. Pure Swing — it knows nothing about Burp and talks to the
 * extension through {@link Actions}, so it can be constructed and exercised
 * outside Burp.
 */
final class DeepJsTab extends JPanel {

    /** What the tab can ask the extension to do. */
    interface Actions {
        void sendToRepeater(List<String[]> endpointRows);

        void fetchHiddenNow();

        void analyseProxyHistory();

        void clearAll();

        void settingsChanged();

        void dismissalsChanged();

        void openReleasePage();
    }

    /** A table whose rows are keyed, so a row can be updated in place when the engine learns more. */
    static final class KeyedModel extends AbstractTableModel {
        private final String[] columns;
        private final Map<String, String[]> rows = new LinkedHashMap<>();
        private final List<String> order = new ArrayList<>();

        KeyedModel(String... columns) {
            this.columns = columns;
        }

        void upsert(String key, String[] row) {
            boolean isNew = !rows.containsKey(key);
            rows.put(key, row);
            if (isNew) {
                order.add(key);
                fireTableRowsInserted(order.size() - 1, order.size() - 1);
            } else {
                int i = order.indexOf(key);
                fireTableRowsUpdated(i, i);
            }
        }

        void remove(String key) {
            int i = order.indexOf(key);
            if (i >= 0) {
                order.remove(i);
                rows.remove(key);
                fireTableRowsDeleted(i, i);
            }
        }

        String[] row(int modelIndex) {
            return rows.get(order.get(modelIndex));
        }

        String key(int modelIndex) {
            return order.get(modelIndex);
        }

        String[] get(String key) {
            return rows.get(key);
        }

        void clear() {
            rows.clear();
            order.clear();
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return order.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int c) {
            return columns[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            String[] row = rows.get(order.get(r));
            return c < row.length ? row[c] : "";
        }
    }

    // Endpoint row layout — also what Actions.sendToRepeater receives. A row carries more than the
    // table shows: after the columns comes the code the finding was read from (before, span, after).
    static final int E_METHOD = 0, E_URL = 1, E_QUERY = 2, E_BODY = 3, E_HEADERS = 4, E_KIND = 5, E_SOURCE = 6, E_SEEN = 7,
            E_BEFORE = 8, E_SPAN = 9, E_AFTER = 10;
    static final int S_SEVERITY = 0, S_VALUE = 2, S_SOURCE = 4, S_BEFORE = 6, S_SPAN = 7, S_AFTER = 8;
    static final String ALL_HOSTS = "All hosts";
    private static final int MAX_DISMISSED = 5000;

    final KeyedModel endpoints = new KeyedModel("Method", "URL", "Query", "Body", "Headers", "Found as", "Source", "Requested");
    final KeyedModel secrets = new KeyedModel("Severity", "Type", "Value", "Key", "Source", "Note");
    final KeyedModel scripts = new KeyedModel("Script / source map", "Kind", "Status");
    final KeyedModel hosts = new KeyedModel("Host", "Class", "Service", "Non-production");

    final JCheckBox enabled = new JCheckBox("Analyse responses", true);
    final JCheckBox scopeOnly = new JCheckBox("In-scope only", false);
    final JCheckBox fetchHidden = new JCheckBox("Fetch hidden scripts", true);
    final JCheckBox fetchMaps = new JCheckBox("Fetch source maps", true);
    final JCheckBox raiseIssues = new JCheckBox("Report secrets as issues", true);
    final JCheckBox showStrings = new JCheckBox("Show string-only paths", false);
    final JCheckBox onlyUnrequested = new JCheckBox("Only not requested yet", false);
    final JCheckBox withSession = new JCheckBox("Borrow the browser's session", true);
    final JCheckBox showDismissed = new JCheckBox("Show dismissed", false);
    final JComboBox<String> hostFilter = new JComboBox<>(new DefaultComboBoxModel<>(new String[]{ALL_HOSTS}));
    final JCheckBox updateCheck = new JCheckBox("Check for updates when Burp starts", true);
    final JButton updateButton = new JButton("Open download page");
    final JCheckBox maskValues = new JCheckBox("Mask values", false);

    private final JLabel status = new JLabel("starting…");
    private final JTextArea other = new JTextArea();
    private final JTextArea log = new JTextArea();
    private final JTabbedPane tabs = new JTabbedPane();
    final JTextField filter = new JTextField(22);
    final JTable endpointTable = new JTable(endpoints);
    final JTable secretTable = new JTable(secrets);
    final CodeView endpointCode = new CodeView();
    final CodeView secretCode = new CodeView();
    private final TableRowSorter<KeyedModel> endpointSorter = new TableRowSorter<>(endpoints);
    private final TableRowSorter<KeyedModel> secretSorter = new TableRowSorter<>(secrets);
    private final TreeSet<String> knownHosts = new TreeSet<>();
    private final Set<String> dismissed = Collections.synchronizedSet(new LinkedHashSet<>());    // secrets the user ruled out
    private final Map<String, List<String>> otherItems = new LinkedHashMap<>();
    private final Actions actions;

    DeepJsTab(Actions actions) {
        super(new BorderLayout(0, 4));
        this.actions = actions;
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        add(toolbar(), BorderLayout.NORTH);
        add(tabs, BorderLayout.CENTER);

        tabs.addTab("API calls", endpointPanel());
        tabs.addTab("Secrets", secretsPanel());
        tabs.addTab("Hidden scripts", scriptsPanel());
        tabs.addTab("Hosts", tablePanel(hosts, new int[]{320, 110, 110, 110}));
        tabs.addTab("Routes · GraphQL · packages", textPanel(other));
        tabs.addTab("Log / settings", settingsPanel());

        for (KeyedModel m : new KeyedModel[]{endpoints, secrets, scripts, hosts}) {
            // later: the tables hear about a change after this listener does, and the titles count what they show
            m.addTableModelListener(e -> SwingUtilities.invokeLater(this::refreshTitles));
        }
        applyFilter();
        applySecretFilter();
        showEndpointCode();
        showSecretCode();
    }

    // ── layout ───────────────────────────────────────────────────────────────

    private JPanel toolbar() {
        JPanel bar = new JPanel(new WrapLayout());
        for (JCheckBox box : new JCheckBox[]{enabled, scopeOnly, fetchHidden, fetchMaps, raiseIssues}) {
            box.addActionListener(e -> actions.settingsChanged());
            bar.add(box);
        }
        enabled.setToolTipText("Analyse every JavaScript / HTML response that passes through Burp");
        scopeOnly.setToolTipText("Ignore responses and never fetch anything outside the target scope");
        fetchHidden.setToolTipText("Request, through Burp, the chunks the bundler names but no page has loaded yet");
        fetchMaps.setToolTipText("Request source maps for analysed scripts and analyse the original sources");
        raiseIssues.setToolTipText("Add an issue to the site map for each non-public secret (shown by Burp Professional)");
        bar.add(Box.createHorizontalStrut(10));
        bar.add(button("Analyse proxy history", e -> actions.analyseProxyHistory()));
        bar.add(button("Clear", e -> actions.clearAll()));
        bar.add(Box.createHorizontalStrut(10));
        bar.add(status);
        return bar;
    }

    private static JButton button(String text, java.awt.event.ActionListener l) {
        JButton b = new JButton(text);
        b.addActionListener(l);
        return b;
    }

    private JPanel endpointPanel() {
        endpointTable.setRowSorter(endpointSorter);
        endpointSorter.setSortsOnUpdates(true);             // a call that has just been requested may no longer belong in the list
        endpointTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        endpointTable.setAutoCreateColumnsFromModel(false);
        widths(endpointTable, new int[]{70, 520, 160, 180, 150, 80, 320, 80});
        endpointTable.getColumnModel().getColumn(E_METHOD).setCellRenderer(new MethodRenderer());
        endpointTable.getColumnModel().getColumn(E_SEEN).setCellRenderer(new SeenRenderer());
        endpointTable.moveColumn(E_SEEN, E_URL + 1);
        endpointTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showEndpointCode();
            }
        });

        filter.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyFilter(); }
            public void removeUpdate(DocumentEvent e) { applyFilter(); }
            public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        showStrings.addActionListener(e -> {
            actions.settingsChanged();
            applyFilter();
        });
        showStrings.setToolTipText("Paths that appear as strings but were not seen at a recognised call site");
        onlyUnrequested.addActionListener(e -> applyFilter());
        onlyUnrequested.setToolTipText("Hide the calls Burp has already made: what is left is what the application's pages never led you to");
        hostFilter.addActionListener(e -> applyFilter());
        withSession.addActionListener(e -> actions.settingsChanged());
        withSession.setToolTipText("Send to Repeater adds the Cookie, Authorization and CSRF / API-key headers your browser last sent "
                + "to the same host through the proxy. They are kept in memory only.");

        JPanel top = new JPanel(new WrapLayout());
        top.add(new JLabel("Filter:"));
        top.add(filter);
        top.add(hostFilter);
        top.add(showStrings);
        top.add(onlyUnrequested);
        top.add(Box.createHorizontalStrut(10));
        top.add(button("Send to Repeater", e -> actions.sendToRepeater(selectedEndpoints())));
        top.add(withSession);
        top.add(button("Copy URLs", e -> copy(selectedEndpoints(), E_URL)));

        JPopupMenu menu = new JPopupMenu();
        JMenuItem toRepeater = new JMenuItem("Send to Repeater");
        toRepeater.addActionListener(e -> actions.sendToRepeater(selectedEndpoints()));
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> copy(selectedEndpoints(), E_URL));
        menu.add(toRepeater);
        menu.add(copyUrl);
        endpointTable.setComponentPopupMenu(menu);

        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(above(endpointTable, endpointCode), BorderLayout.CENTER);
        return p;
    }

    /** A table with, under it, the code its selected row was read from. */
    private static JSplitPane above(JTable table, CodeView code) {
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), code);
        split.setResizeWeight(0.72);
        split.setBorder(null);
        return split;
    }

    private JPanel scriptsPanel() {
        JPanel top = new JPanel(new WrapLayout());
        top.add(new JLabel("Scripts and source maps the analysed code refers to — the parts of the app no page has loaded."));
        top.add(button("Fetch now", e -> actions.fetchHiddenNow()));
        JPanel p = tablePanel(scripts, new int[]{760, 110, 180});
        p.add(top, BorderLayout.NORTH);
        return p;
    }

    /** How a secret is written when it must not be readable over a shoulder or in a screenshot. */
    static String mask(String value) {
        int n = value.codePointCount(0, value.length());
        int head = n <= 8 ? 2 : n <= 20 ? 4 : 8, tail = n <= 8 ? 0 : n <= 20 ? 2 : 4;
        return value.substring(0, value.offsetByCodePoints(0, Math.min(head, n))) + "…"
                + value.substring(value.offsetByCodePoints(value.length(), -tail));
    }

    private JPanel secretsPanel() {
        secretTable.setRowSorter(secretSorter);
        widths(secretTable, new int[]{70, 190, 320, 140, 300, 420});
        secretTable.setDefaultRenderer(Object.class, new SecretRenderer());
        JPopupMenu menu = copyCellMenu(secretTable);
        JMenuItem dismiss = new JMenuItem("Not a secret: hide it, here and from now on");
        dismiss.addActionListener(e -> dismissSelected(true));
        JMenuItem restore = new JMenuItem("A secret after all: bring it back");
        restore.addActionListener(e -> dismissSelected(false));
        menu.add(dismiss);
        menu.add(restore);
        secretTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSecretCode();
            }
        });

        maskValues.setToolTipText("Show only the first and last characters of each value, in the table and in the code under it "
                + "(for screenshots and screen sharing). \"Copy cell\" still copies the whole value.");
        maskValues.addActionListener(e -> {
            actions.settingsChanged();
            secretTable.repaint();
            showSecretCode();
            showEndpointCode();
        });
        showDismissed.setToolTipText("Also list the values you marked \"Not a secret\" (in grey). The choice is remembered by value, "
                + "so the same value is not reported again on another site.");
        showDismissed.addActionListener(e -> applySecretFilter());

        JPanel top = new JPanel(new WrapLayout());
        top.add(new JLabel("Values are shown as found. Nothing found is ever sent anywhere or tried."));
        top.add(maskValues);
        top.add(showDismissed);
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(above(secretTable, secretCode), BorderLayout.CENTER);
        return p;
    }

    private JPanel tablePanel(KeyedModel model, int[] columnWidths) {
        JTable t = new JTable(model);
        t.setAutoCreateRowSorter(true);
        widths(t, columnWidths);
        copyCellMenu(t);
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JScrollPane(t), BorderLayout.CENTER);
        return p;
    }

    /** Cells can be selected one at a time, and the context menu copies the one selected. */
    private static JPopupMenu copyCellMenu(JTable t) {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copyCell = new JMenuItem("Copy cell");
        copyCell.addActionListener(e -> {
            int r = t.getSelectedRow(), c = t.getSelectedColumn();
            if (r >= 0 && c >= 0) {
                clipboard(String.valueOf(t.getValueAt(r, c)));     // the value itself, masked on screen or not
            }
        });
        menu.add(copyCell);
        t.setComponentPopupMenu(menu);
        t.setCellSelectionEnabled(true);
        return menu;
    }

    private static JPanel textPanel(JTextArea area) {
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JScrollPane(area), BorderLayout.CENTER);
        return p;
    }

    private JPanel settingsPanel() {
        JPanel top = new JPanel(new WrapLayout());
        top.add(updateCheck);
        updateCheck.setToolTipText("One request to api.github.com, sent through Burp, to see whether a newer DeepJS has been released");
        updateCheck.addActionListener(e -> actions.settingsChanged());
        updateButton.setToolTipText("Opens the release page in your browser. DeepJS downloads and replaces nothing itself.");
        updateButton.addActionListener(e -> actions.openReleasePage());
        updateButton.setVisible(false);                 // until a newer release is known
        top.add(updateButton);
        JPanel p = textPanel(log);
        p.add(top, BorderLayout.NORTH);
        return p;
    }

    private static void widths(JTable t, int[] w) {
        for (int i = 0; i < w.length && i < t.getColumnModel().getColumnCount(); i++) {
            t.getColumnModel().getColumn(i).setPreferredWidth(w[i]);
        }
    }

    // ── behaviour ────────────────────────────────────────────────────────────

    private static String cell(String[] row, int column) {
        return column < row.length ? row[column] : "";
    }

    /** Which API calls are listed: the text typed, one host, with or without bare strings, requested or not. */
    private void applyFilter() {
        String text = filter.getText().trim().toLowerCase(Locale.ROOT);
        Object chosen = hostFilter.getSelectedItem();
        String host = chosen == null || ALL_HOSTS.equals(chosen) ? null : chosen.toString();
        boolean strings = showStrings.isSelected(), unrequested = onlyUnrequested.isSelected();
        endpointSorter.setRowFilter(new RowFilter<KeyedModel, Integer>() {
            @Override
            public boolean include(Entry<? extends KeyedModel, ? extends Integer> entry) {
                String[] row = endpoints.row(entry.getIdentifier());
                if ((!strings && cell(row, E_KIND).equals("string")) || (unrequested && cell(row, E_SEEN).equals("yes"))
                        || (host != null && !host.equals(Traffic.hostOf(cell(row, E_URL))))) {
                    return false;
                }
                if (text.isEmpty()) {
                    return true;
                }
                for (int c = 0; c <= E_SOURCE; c++) {
                    if (cell(row, c).toLowerCase(Locale.ROOT).contains(text)) {
                        return true;
                    }
                }
                return false;
            }
        });
        refreshTitles();
    }

    private void applySecretFilter() {
        boolean all = showDismissed.isSelected();
        secretSorter.setRowFilter(new RowFilter<KeyedModel, Integer>() {
            @Override
            public boolean include(Entry<? extends KeyedModel, ? extends Integer> entry) {
                return all || !dismissed.contains(secrets.key(entry.getIdentifier()));
            }
        });
        refreshTitles();
    }

    /** The row the selection rests on, or null. */
    private static String[] selected(JTable table, KeyedModel model) {
        int viewRow = table.getSelectionModel().getLeadSelectionIndex();
        if (viewRow < 0 || viewRow >= table.getRowCount() || !table.getSelectionModel().isSelectedIndex(viewRow)) {
            return null;
        }
        return model.row(table.convertRowIndexToModel(viewRow));
    }

    private static boolean hasCode(String[] row, int before) {
        return !(cell(row, before) + cell(row, before + 1) + cell(row, before + 2)).isEmpty();
    }

    private void showEndpointCode() {
        String[] row = selected(endpointTable, endpoints);
        if (row == null) {
            endpointCode.clear("Select a call to see the code it was read from.");
        } else if (!hasCode(row, E_BEFORE)) {
            endpointCode.clear(cell(row, E_SOURCE) + "  ·  not read from script code (an HTML form, robots.txt, a sitemap)");
        } else {
            endpointCode.show(cell(row, E_SOURCE) + "  ·  found as " + cell(row, E_KIND),
                    cell(row, E_BEFORE), cell(row, E_SPAN), cell(row, E_AFTER), concealed());
        }
    }

    private void showSecretCode() {
        String[] row = selected(secretTable, secrets);
        if (row == null) {
            secretCode.clear("Select a value to see the code it was read from.");
        } else if (!hasCode(row, S_BEFORE)) {
            secretCode.clear(cell(row, S_SOURCE));
        } else {
            secretCode.show(cell(row, S_SOURCE), cell(row, S_BEFORE), cell(row, S_SPAN), cell(row, S_AFTER), concealed());
        }
    }

    /** With "Mask values" on, no value in the Secrets table may be readable in a code view either. */
    private List<String> concealed() {
        List<String> values = new ArrayList<>();
        if (maskValues.isSelected()) {
            for (int r = 0; r < secrets.getRowCount(); r++) {
                values.add(cell(secrets.row(r), S_VALUE));
            }
        }
        return values;
    }

    private void dismissSelected(boolean dismiss) {
        List<String> ids = new ArrayList<>();
        for (int viewRow : secretTable.getSelectedRows()) {
            ids.add(secrets.key(secretTable.convertRowIndexToModel(viewRow)));
        }
        if (dismiss ? !dismissed.addAll(ids) : !dismissed.removeAll(ids)) {
            return;
        }
        synchronized (dismissed) {
            for (Iterator<String> oldest = dismissed.iterator(); dismissed.size() > MAX_DISMISSED; oldest.remove()) {
                oldest.next();
            }
        }
        applySecretFilter();
        secretTable.repaint();
        actions.dismissalsChanged();
    }

    /** Has the user ruled this secret out? `id`: its key in the secrets table (type + fingerprint). Any thread. */
    boolean isDismissed(String id) {
        return dismissed.contains(id);
    }

    List<String> dismissedIds() {
        synchronized (dismissed) {
            return new ArrayList<>(dismissed);
        }
    }

    void setDismissed(Collection<String> ids) {
        dismissed.clear();
        dismissed.addAll(ids);
    }

    /** Options and dismissals were set from saved preferences, not by a click: list accordingly. */
    void settingsLoaded() {
        onEdt(() -> {
            applyFilter();
            applySecretFilter();
        });
    }

    List<String[]> selectedEndpoints() {
        List<String[]> out = new ArrayList<>();
        for (int viewRow : endpointTable.getSelectedRows()) {
            out.add(endpoints.row(endpointTable.convertRowIndexToModel(viewRow)));
        }
        return out;
    }

    private void copy(List<String[]> rows, int column) {
        StringBuilder b = new StringBuilder();
        for (String[] r : rows) {
            b.append(r[column]).append('\n');
        }
        clipboard(b.toString().trim());
    }

    private static void clipboard(String text) {
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        } catch (RuntimeException ignored) {
            // no clipboard (headless) — nothing to copy to
        }
    }

    private void refreshTitles() {
        int shown = endpointTable.getRowCount(), all = endpoints.getRowCount();
        tabs.setTitleAt(0, "API calls (" + (shown == all ? "" : shown + " of ") + all + ")");
        tabs.setTitleAt(1, "Secrets (" + secretTable.getRowCount() + ")");
        tabs.setTitleAt(2, "Hidden scripts (" + scripts.getRowCount() + ")");
        tabs.setTitleAt(3, "Hosts (" + hosts.getRowCount() + ")");
    }

    private static void onEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeLater(r);
        }
    }

    // ── updates from the extension (any thread) ──────────────────────────────

    void putEndpoint(String key, String[] row) {
        onEdt(() -> {
            endpoints.upsert(key, row);
            String host = Traffic.hostOf(cell(row, E_URL));
            if (!host.isEmpty() && knownHosts.add(host)) {
                // kept in order; inserting does not disturb what is selected
                ((DefaultComboBoxModel<String>) hostFilter.getModel())
                        .insertElementAt(host, 1 + knownHosts.headSet(host).size());
            }
        });
    }

    /** Burp has now made a request for each of these endpoints. */
    void markRequested(Collection<String> keys) {
        onEdt(() -> {
            for (String key : keys) {
                String[] row = endpoints.get(key);
                if (row != null && row.length > E_SEEN && !row[E_SEEN].equals("yes")) {
                    String[] requested = row.clone();
                    requested[E_SEEN] = "yes";
                    endpoints.upsert(key, requested);
                }
            }
        });
    }

    void removeEndpoint(String key) {
        onEdt(() -> endpoints.remove(key));
    }

    void putSecret(String key, String[] row) {
        onEdt(() -> secrets.upsert(key, row));
    }

    void putScript(String url, String kind, String state) {
        onEdt(() -> scripts.upsert(url, new String[]{url, kind, state}));
    }

    void putHost(String[] row) {
        onEdt(() -> hosts.upsert(row[0], row));
    }

    void putOther(String section, String item) {
        onEdt(() -> {
            List<String> items = otherItems.computeIfAbsent(section, k -> new ArrayList<>());
            if (items.contains(item)) {
                return;
            }
            items.add(item);
            StringBuilder b = new StringBuilder();
            otherItems.forEach((name, list) -> {
                b.append(name).append(" (").append(list.size()).append(")\n");
                list.forEach(i -> b.append("    ").append(i).append('\n'));
                b.append('\n');
            });
            other.setText(b.toString());
            other.setCaretPosition(0);
        });
    }

    void log(String line) {
        onEdt(() -> {
            if (log.getLineCount() > 2000) {
                log.setText("");
            }
            log.append(line + "\n");
        });
    }

    /** A newer release exists: offer the page it is downloaded from. */
    void offerUpdate(String version) {
        onEdt(() -> {
            updateButton.setText("Get DeepJS " + version);
            updateButton.setVisible(true);
        });
    }

    /** Installed from the BApp Store: Burp updates the extension, so there is nothing for it to check. */
    void updatesComeFromTheStore() {
        onEdt(() -> {
            updateCheck.setEnabled(false);
            updateCheck.setToolTipText("Installed from the BApp Store: Burp keeps this extension up to date");
        });
    }

    /** Everything logged so far (call on the event dispatch thread). */
    String logText() {
        return log.getText();
    }

    void setStatus(String text, boolean healthy) {
        onEdt(() -> {
            status.setText(text);
            status.setForeground(healthy ? new Color(0x2E7D32) : new Color(0xC62828));
        });
    }

    void clearTables() {
        onEdt(() -> {
            endpoints.clear();
            secrets.clear();
            scripts.clear();
            hosts.clear();
            otherItems.clear();
            other.setText("");
            knownHosts.clear();
            hostFilter.setModel(new DefaultComboBoxModel<>(new String[]{ALL_HOSTS}));
            applyFilter();
        });
    }

    void forEachOption(Consumer<JCheckBox> c) {
        for (JCheckBox box : new JCheckBox[]{enabled, scopeOnly, fetchHidden, fetchMaps, raiseIssues, updateCheck, maskValues,
                showStrings, withSession}) {
            c.accept(box);
        }
    }

    // ── renderers ────────────────────────────────────────────────────────────

    private static final class MethodRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
            Component comp = super.getTableCellRendererComponent(t, v, sel, focus, r, c);
            String m = String.valueOf(v);
            if (!sel) {
                comp.setForeground(switch (m) {
                    case "GET" -> new Color(0x2E7D32);
                    case "POST", "PUT", "PATCH" -> new Color(0xB26A00);
                    case "DELETE" -> new Color(0xC62828);
                    default -> Color.GRAY;
                });
            }
            setFont(getFont().deriveFont(Font.BOLD));
            return comp;
        }
    }

    /** "no" is the answer worth noticing: a call the code makes that nobody has made yet. */
    private static final class SeenRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
            Component comp = super.getTableCellRendererComponent(t, v, sel, focus, r, c);
            boolean pending = "no".equals(v);
            if (!sel) {
                comp.setForeground(pending ? new Color(0xB26A00) : Color.GRAY);
            }
            setFont(getFont().deriveFont(pending ? Font.BOLD : Font.PLAIN));
            return comp;
        }
    }

    /** Every cell of the secrets table: severity in colour, the value masked on request, a dismissed row in grey. */
    private final class SecretRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
            int column = t.convertColumnIndexToModel(c);
            String text = String.valueOf(v);
            Component comp = super.getTableCellRendererComponent(
                    t, column == S_VALUE && maskValues.isSelected() ? mask(text) : text, sel, focus, r, c);
            boolean gone = dismissed.contains(secrets.key(t.convertRowIndexToModel(r)));
            if (!sel) {
                Color colour = t.getForeground();
                if (gone) {
                    colour = Color.GRAY;
                } else if (column == S_SEVERITY) {
                    colour = switch (text) {
                        case "critical", "high" -> new Color(0xC62828);
                        case "medium" -> new Color(0xB26A00);
                        case "low" -> new Color(0x1565C0);
                        default -> Color.GRAY;
                    };
                }
                comp.setForeground(colour);
            }
            setFont(getFont().deriveFont(gone ? Font.ITALIC : Font.PLAIN));
            return comp;
        }
    }
}
